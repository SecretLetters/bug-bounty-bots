#!/usr/bin/env python3
"""Rank public CVE-with-PoC findings by research-priority for triage.

This is a read-only aggregator over already-public CVE and proof-of-concept
metadata produced by cve-poc-feed.py and cve-program-match.py. It assigns each
finding a 1-10 research-priority score so a hunter can decide which published
advisories are worth limited time to study and reproduce in authorized testing.

It may fetch public GitHub README files and public nuclei YAML templates to
judge how much engineering a reproduction would take. It never executes a PoC,
never compiles or runs exploit code, never scans, and never sends a request to
any target system.

Scoring formula
---------------
Two sub-scores, each 1-10, then a weighted combination:

  research_priority = clamp(1, 10, round(
      0.65 * reproduction_complexity + 0.35 * prevalence
  ))

Reproduction complexity (B) is weighted higher because low-effort-to-reproduce
disclosures are the best learning/triage candidates; a hard native exploit on
a popular product still ranks low.

  A) Prevalence / relevance — how commonly the *affected component* shows up
     in authorized bounty-program scopes and on the public internet, from
     public data only. Built as:

       prevalence = clamp(1, 10, round(
           0.60 * product_popularity + 0.40 * match_signal
       ))

     product_popularity (1-10) is a coarse prior: ubiquitous internet-facing
     platforms (Tomcat, Next.js, WordPress core, SharePoint, PHP) score high;
     popular apps/plugins mid; long-tail CMS extensions low; libraries,
     drivers, and deep dependencies lower still. Issues that only apply to
     internal/cluster/adjacent-network configurations are capped.

     match_signal (1-10) uses program-match *quality*, not raw count:
     first-party / high-confidence exact-product hits count a lot; a pile of
     medium "this program runs WordPress, confirm the plugin is in use"
     matches counts little, because they do not show the affected component
     is actually deployed.

  B) Reproduction complexity of the *public* PoC — how much engineering it
     would take to reproduce the disclosed issue in a lab or an authorized
     test, judged by reading the public PoC repo README plus the CVE
     description (and a nuclei template, when one is already indexed).
     10 = a single, fully self-contained unauthenticated HTTP request
     documented in the advisory (e.g. a path-traversal GET), minimal setup.
     Lower scores for lab build-outs, memory-corruption/heap-grooming,
     compiled exploits, non-default configuration, or multi-step chains.

If every listed PoC repository is unreachable, the finding is left
"unrated, repo unreachable" rather than guessed high.

Examples:
  python3 rank-findings.py
  python3 rank-findings.py --days 14 --limit 12
  python3 rank-findings.py --verbose --days 14 --limit 12
  python3 rank-findings.py --json --min-score 7
  python3 rank-findings.py --feed-json state/cve-poc-feed-14d.priv-unauth.json --match-json state/cve-program-match-14d.priv-unauth.json
"""

from __future__ import annotations

import argparse
import os
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
from privilege import (  # noqa: E402
    add_priv_level_argument,
    filter_feed_payload,
    filter_note,
    privilege_tag_from_record,
)
import poc_trust  # noqa: E402
import vuln_types  # noqa: E402
from paths import (  # noqa: E402
    SCRIPT_DIR,
    bounty_targets_repo,
    ensure_bounty_targets,
    resolve_base,
    state_dir as default_state_dir,
)


# Scripts always live next to this file. Data uses the configurable base dir.
FEED_SCRIPT = SCRIPT_DIR / "cve-poc-feed.py"
MATCH_SCRIPT = SCRIPT_DIR / "cve-program-match.py"
DEFAULT_STATE_DIR = default_state_dir()
DEFAULT_REPO = bounty_targets_repo()
ET = ZoneInfo("America/New_York")
USER_AGENT = (
    "bounty-pipeline-rank-findings/1.0 "
    "(read-only public metadata; does not execute PoCs or scan hosts)"
)
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/{cve_id}"
CACHE_NAME = "poc-readme-cache.json"

# research_priority = clamp(1, 10, round(W_REPRO * B + W_PREV * A))
W_REPRO = 0.65
W_PREV = 0.35

# ---------------------------------------------------------------------------
# Product popularity priors (affected component, not the parent CMS).
# Matched as case-insensitive substrings against "vendor product" labels.
# ---------------------------------------------------------------------------

# Ubiquitous, internet-facing, typically passively fingerprintable.
POPULARITY_HIGH = (
    "apache tomcat", "tomcat", "apache httpd", "apache http server",
    "nginx", "php-fpm", "php group php", "wordpress", "wordpress core",
    "next.js", "nextjs", "joomla", "drupal", "sharepoint",
    "microsoft sharepoint", "exchange", "microsoft exchange",
    "jenkins", "gitlab", "confluence", "jira", "spring boot", "spring framework",
    "laravel", "django", "rails", "asp.net", "iis", "weblogic", "websphere",
    "keycloak", "grafana", "elasticsearch", "kibana", "mongodb",
    "postgresql", "postgres", "mysql", "mariadb", "redis",
    "vercel", "cloudflare",
)

# Common internet-facing products / widely used plugins and apps.
POPULARITY_COMMON = (
    "woocommerce", "elementor", "contact form 7", "yoast", "jetpack",
    "ninja forms", "forminator", "wpforms", "gravity forms", "buddypress",
    "woocommerce", "litespeed", "wordfence", "wpml", "rank math",
    "etherpad", "portainer", "nextcloud", "owncloud", "grafana",
    "vault", "authentik", "okta", "minio", "rancher", "harbor",
    "sonarqube", "airflow", "metabase", "strapi", "directus", "ghost",
    "magento", "adobe commerce", "prestashop", "opencart",
    "mattermost", "discourse", "mediawiki", "roundcube", "zimbra",
    "phpmyadmin", "adminer", "cpanel", "plesk", "webmin",
    "ivanti", "citrix", "netscaler", "fortinet", "palo alto",
    "moveit", "manageengine", "servicenow",
)

# Moderately known components (known plugins/themes/apps, not ubiquitous).
POPULARITY_MODERATE = (
    "soledad", "masteriyo", "arforms", "webtoffee", "automatorwp",
    "nexter blocks", "buddyboss",
)

# Libraries, drivers, SDKs, and other deep dependencies.
LIBRARY_HINTS = (
    "driver", "sdk", "library", "anti csrf", "anticsrf", "npm package",
    "python package", "crates.io", "go module", "ruby gem",
)

# Issue applies mainly to internal, cluster, or adjacent-network setups.
INTERNAL_HINTS = (
    "join a cluster", "cluster communication", "cluster was secured",
    "encryptinterceptor", "tls-psk", "adjacent network", "local only",
    "requires local access", "not remotely exploitable",
    "dns srv", "forge or change the dns", "man-in-the-middle",
    "man in the middle", "on-path attacker", "bgp ",
)

CMS_EXTENSION_RE = re.compile(
    r"\b(plugin|theme|extension|add-?on|module)\b.*\b(wordpress|joomla|drupal|magento)\b"
    r"|\b(wordpress|joomla|drupal|magento)\b.*\b(plugin|theme|extension|add-?on|module)\b"
    r"|\bplugin for wordpress\b"
    r"|\bwordpress plugin\b"
    r"|\btheme for wordpress\b",
    re.I,
)

THIRD_PARTY_REASON_RE = re.compile(
    r"third-party\s+(wordpress|joomla|drupal|magento)\s+extension"
    r"|confirm the affected component is actually in use",
    re.I,
)

# ---------------------------------------------------------------------------
# Reproduction-complexity signals, applied to advisory + README text only.
# ---------------------------------------------------------------------------

# Hard caps: the *class* of issue cannot be a copy-paste browser GET.
HARD_CAPS: list[tuple[int, str, re.Pattern[str]]] = [
    (1, "kernel/browser-engine/hypervisor chain",
     re.compile(r"\b(linux kernel|windows kernel|hypervisor|webkit|v8 engine|"
                r"javascript engine|chrome renderer|sandbox escape)\b", re.I)),
    (2, "heap-grooming / ASLR-bypass memory corruption",
     re.compile(r"\b(heap groom|heap spray|aslr bypass|info leak.{0,40}aslr|"
                r"arbitrary read.{0,40}write)\b", re.I)),
    (3, "memory-corruption / compiled native exploit",
     re.compile(r"\b(use[- ]after[- ]free|buffer overflow|out[- ]of[- ]bounds "
                r"(write|read)|integer overflow|memory corruption|"
                r"heap overflow|stack overflow|type confusion)\b", re.I)),
    (3, "needs a privileged network position (DNS/MitM/cluster join)",
     re.compile(r"\b(forge or change the dns|dns srv|spoof(ed)? dns|"
                r"man[- ]in[- ]the[- ]middle|on[- ]path attacker|"
                r"join a cluster|cluster (communication|was secured)|"
                r"encryptinterceptor|unauthenticated node to join)\b", re.I)),
    (3, "supply-chain / C2 backdoor, not a self-contained request",
     re.compile(r"\b(embedded malicious code|backdoor module|command-and-control|"
                r"command and control|in control of the remote server|"
                r"no patched versions)\b", re.I)),
    (5, "HTTP request smuggling / response desync, needs a proxy lab",
     re.compile(r"\b(request smuggling|response smuggling|desynchroniz|"
                r"http/?1\.1 reverse proxy|pipelined response|"
                r"content[- ]length.{0,30}chunked|cwe-444)\b", re.I)),
    (5, "race condition or timing-sensitive trigger",
     re.compile(r"\b(race condition|toctou|time[- ]of[- ]check)\b", re.I)),
]

# "Path traversal" / "curl ... http" alone is not a 10: those strings appear in
# chains, auth-bypass writeups, and incidental README examples (e.g. a webshell
# login). A 10 requires explicit single-GET / URL-path language.
EASY_SIGNALS: list[tuple[int, str, re.Pattern[str]]] = [
    (10, "advisory documents a single unauthenticated GET / URL-path trigger",
     re.compile(r"\b(single get request|with a single get request|"
                r"with a single get\b|one get request|"
                r"in the url path|paste.{0,20}(in(to)? the )?(browser|url)|"
                r"payload of the form .{0,60} in the url)\b", re.I)),
    (9, "single documented unauthenticated HTTP request",
     re.compile(r"\b(single (unauthenticated )?(http|https) request|"
                r"a single (crafted )?(get|post) request|"
                r"one unauthenticated (http )?request|"
                r"one[- ]request (trigger|exploit|poc))\b", re.I)),
    (8, "straightforward unauthenticated HTTP (form/AJAX/parameter)",
     re.compile(r"\b(unauthenticated attackers? (can|to|who)|"
                r"an unauthenticated attacker|"
                r"without authentica|"
                r"available to logged-out users|"
                r"crafted (registration )?post|ajax action|"
                r"file upload|sql injection|stored cross-site|"
                r"change the password|reset the password|"
                r"arbitrary file (deletion|delete|read))\b", re.I)),
]

SETUP_PENALTIES: list[tuple[int, str, re.Pattern[str]]] = [
    (2, "needs a non-default configuration",
     re.compile(r"\b(non-default configuration|non[- ]default|"
                r"fresh installs?.{0,40}false|"
                r"requires that the site has .{0,80}true|"
                r"only exploitable when|"
                r"this is only exploitable when|"
                r"user registration is enabled|"
                r"documented, supported plugin configuration|"
                r"must be .{0,40}enabled and configured)\b", re.I)),
    (1, "needs companion plugins or a specific published component",
     re.compile(r"\b(must have .{0,80} (active|installed)|"
                r"alongside this plugin|"
                r"requires (the|a) .{0,60}(to be )?(installed and active|"
                r"published form)|"
                r"buddypress and paid memberships|"
                r"elementor active|requires elementor)\b", re.I)),
    (2, "PoC is a lab build / docker environment rather than a request",
     re.compile(r"\b(docker[- ]compose|vagrant|build the (lab|target)|"
                r"compile the exploit|requires a local lab|"
                r"complete, deterministic reproduction \(docker lab)\b", re.I)),
    (1, "multi-step chain (nonce harvest + follow-up request, or similar)",
     re.compile(r"\b(after which a single|full exploit chain|"
                r"nonce retrieval|harvest the publicly emitted|"
                r"two[- ]step|multi[- ]step)\b", re.I)),
    (1, "needs a victim pre-condition (e.g. an active session)",
     re.compile(r"\b(active app session|has an active session|"
                r"when that user has an active)\b", re.I)),
]

DESER_RE = re.compile(
    r"\b(php object injection|object injection|insecure deserialization|"
    r"maybe_unserialize|unserialize\(|object injection)\b",
    re.I,
)
COMPILED_RE = re.compile(
    r"\b(\.c\b|\.cpp\b|\.rs\b|gcc |clang |msbuild |exploit\.exe|"
    r"pre-compiled|precompiled binary)\b",
    re.I,
)
SINGLE_GET_RE = re.compile(
    r"\b(single get request|with a single get|in the url path|"
    r"payload of the form .{0,40} in the url)\b",
    re.I,
)
THIN_README_MAX = 280


def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def now_et() -> datetime:
    return datetime.now(ET)


def fmt_et(dt: datetime | None) -> str:
    if dt is None:
        return "unknown"
    return dt.astimezone(ET).strftime("%Y-%m-%d %H:%M ET")


def clamp(n: int, lo: int = 1, hi: int = 10) -> int:
    return max(lo, min(hi, n))


def round_score(value: float) -> int:
    """Half-up rounding to an int in 1..10."""
    return clamp(int(value + 0.5))


def one_line(text: str, limit: int = 160) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    cut = text[: limit - 1]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut + "…"


def md_link(label: str, url: str | None) -> str:
    text = (label or "").replace("[", "\\[").replace("]", "\\]")
    if url:
        return f"[{text}]({url})"
    return text


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def cvss_text(item: dict[str, Any]) -> str:
    cvss = item.get("cvss")
    if cvss is None:
        return item.get("severity") or "N/A"
    try:
        return f"{float(cvss):.1f}"
    except (TypeError, ValueError):
        return str(cvss)


# ---------------------------------------------------------------------------
# HTTP (public advisory / repo metadata only)
# ---------------------------------------------------------------------------

def http_get(url: str, *, timeout: int = 15, accept: str | None = None) -> tuple[int, str] | None:
    """GET a public URL. Returns (status, body) or None on network error.

    Only used for public GitHub / raw.githubusercontent.com documentation.
    Never pointed at a bounty target or arbitrary host supplied as a scope.
    """
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(80_000)
            charset = "utf-8"
            ctype = resp.headers.get_content_charset()
            if ctype:
                charset = ctype
            try:
                body = raw.decode(charset, errors="replace")
            except LookupError:
                body = raw.decode("utf-8", errors="replace")
            return int(resp.status), body
    except urllib.error.HTTPError as exc:
        try:
            exc.read()
        except Exception:
            pass
        return int(exc.code), ""
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def load_cache(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"fetched_at": None, "repos": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"fetched_at": None, "repos": {}}
    if not isinstance(data, dict):
        return {"fetched_at": None, "repos": {}}
    data.setdefault("repos", {})
    return data


def save_cache(path: Path, cache: dict[str, Any]) -> None:
    cache["fetched_at"] = now_et().isoformat()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(cache, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Load feed + match JSON
# ---------------------------------------------------------------------------

def run_json(cmd: list[str], *, timeout: int) -> dict[str, Any]:
    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    try:
        proc = subprocess.run(
            cmd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        die(f"Command timed out after {timeout}s: {' '.join(cmd)}")
    except OSError as exc:
        die(f"Failed to run {cmd[0]}: {exc}")
    if proc.stderr:
        sys.stderr.write(proc.stderr)
        if not proc.stderr.endswith("\n"):
            sys.stderr.write("\n")
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        die(f"Command failed ({proc.returncode}): {err or ' '.join(cmd)}")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        die(f"Command did not return JSON: {' '.join(cmd)} ({exc})")
    if not isinstance(data, dict):
        die(f"Command returned a JSON {type(data).__name__}, expected an object")
    return data


def load_json_file(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        die(f"Could not read {path}: {exc}")
    except json.JSONDecodeError as exc:
        die(f"Invalid JSON in {path}: {exc}")
    if not isinstance(data, dict):
        die(f"{path} is not a JSON object")
    return data


def default_feed_path(state_dir: Path, days: int, priv_level: str) -> Path:
    return state_dir / f"cve-poc-feed-{days}d.priv-{priv_level}.json"


def default_match_path(state_dir: Path, days: int, priv_level: str) -> Path:
    return state_dir / f"cve-program-match-{days}d.priv-{priv_level}.json"


# ---------------------------------------------------------------------------
# Prevalence
# ---------------------------------------------------------------------------

def _label_hits(label: str, terms: tuple[str, ...]) -> bool:
    n = normalize(label)
    if not n:
        return False
    for term in terms:
        t = normalize(term)
        if t and t in n:
            return True
    return False


# Parent CMS/platform tokens. A plugin named "ELEX WordPress HelpDesk" or
# "Restrictions for BuddyPress" must not inherit the platform's popularity.
PARENT_PLATFORM_TERMS = (
    "wordpress", "wordpress core", "woocommerce", "joomla", "joomla cms",
    "drupal", "buddypress", "magento", "elementor",
)

# Plugins/apps whose *own name* is widely deployed, not just the parent CMS.
KNOWN_CMS_PLUGINS = (
    "ninja forms", "forminator", "woocommerce", "elementor", "contact form 7",
    "yoast", "jetpack", "wpforms", "gravity forms", "wordfence", "wpml",
    "rank math", "litespeed",
)

STUB_REPO_MARKERS = ("cveforge/", "googlesky/", "evenomn/")
STUB_README_HINTS = ("capsule-render.vercel.app", "badge/Author-cveForge")


def is_stub_doc(doc: "RepoDoc | None") -> bool:
    if doc is None:
        return False
    name = (doc.full_name or "").lower()
    if any(m in name for m in STUB_REPO_MARKERS):
        return True
    body = doc.readme or ""
    return any(h.lower() in body.lower() for h in STUB_README_HINTS)


def _strip_parent_platform(product: str) -> str:
    """Product tokens with trailing 'for <CMS>' / bare parent-platform words removed."""
    n = normalize(product)
    n = re.sub(
        r"\s+for\s+(wordpress|woocommerce|joomla|drupal|buddypress|magento|elementor)\b.*$",
        "",
        n,
    )
    n = re.sub(r"\b(wordpress|woocommerces?)\s+(plugin|theme|extension|add ?on)\b", " ", n)
    return " ".join(n.split())


def is_cms_extension(
    product: str,
    description: str,
    pairings: list[dict[str, Any]] | None = None,
) -> bool:
    if pairings and any(THIRD_PARTY_REASON_RE.search(p.get("reason") or "") for p in pairings):
        return True
    n = normalize(product)
    if n in {"wordpress", "wordpress core", "joomla", "joomla cms", "drupal", "magento"}:
        return False
    # "ELEX WordPress HelpDesk" is a plugin, not WordPress core.
    if any(p in n for p in ("wordpress", "joomla", "drupal", "magento")) and n not in {
        "wordpress", "wordpress core", "joomla", "joomla cms", "drupal", "magento",
    }:
        return True
    blob = f"{product} {description}"
    if CMS_EXTENSION_RE.search(blob):
        if re.search(r"\bwordpress core\b", blob, re.I) and n in {"wordpress", "wordpress core"}:
            return False
        return True
    return False


def is_library(product: str, description: str) -> bool:
    blob = normalize(f"{product} {description[:400]}")
    return any(normalize(h) in blob for h in LIBRARY_HINTS)


def is_internal_issue(description: str) -> bool:
    text = description or ""
    return any(h in text.lower() for h in INTERNAL_HINTS)


def product_popularity(
    product: str,
    description: str,
    pairings: list[dict[str, Any]] | None = None,
) -> tuple[int, str]:
    """Return (1-10 prior, short reason) for the affected component."""
    label = product or ""
    if is_library(label, description):
        return 2, "library/driver/deep dependency"
    if is_cms_extension(label, description, pairings):
        self_name = _strip_parent_platform(label) or normalize(label)
        if _label_hits(label, POPULARITY_MODERATE) or _label_hits(self_name, POPULARITY_MODERATE):
            return 4, "moderately known CMS plugin/theme"
        plugin_hits = [t for t in KNOWN_CMS_PLUGINS if normalize(t) in self_name]
        non_parent = [t for t in plugin_hits if normalize(t) not in {normalize(p) for p in PARENT_PLATFORM_TERMS}]
        if non_parent:
            return 6, "widely used CMS plugin/app"
        return 3, "long-tail CMS plugin/theme"
    if _label_hits(label, POPULARITY_HIGH):
        score = 9
        reason = "ubiquitous internet-facing platform"
        if is_internal_issue(description):
            return 4, "popular platform, but issue is cluster/internal-only"
        return score, reason
    if _label_hits(label, POPULARITY_COMMON):
        score = 7
        reason = "common internet-facing product"
        if is_internal_issue(description):
            return 4, "common product, but issue is cluster/internal-only"
        return score, reason
    if _label_hits(label, POPULARITY_MODERATE):
        return 5, "moderately known component"
    # Fallback: web-looking software gets a mid-low prior; unknown stays low.
    if re.search(r"\b(http|web|cms|server|application)\b", description[:400], re.I):
        return 4, "unlisted web component"
    return 3, "niche or unlisted component"


def match_signal(pairings: list[dict[str, Any]]) -> tuple[int, str]:
    """Quality-weighted program-match signal, 1-10."""
    if not pairings:
        return 1, "no program-scope matches"
    high = 0
    first_party = 0
    medium_exact = 0
    family_only = 0
    for p in pairings:
        conf = (p.get("confidence") or "").lower()
        reason = p.get("reason") or ""
        if THIRD_PARTY_REASON_RE.search(reason):
            family_only += 1
            continue
        if p.get("first_party") or conf == "high":
            first_party += 1
        else:
            medium_exact += 1
    if first_party:
        n = first_party
        score = 8 if n == 1 else 10 if n >= 3 else 9
        why = f"{n} high/first-party program match(es)"
        if family_only:
            why += f"; {family_only} weak CMS-family hit(s) ignored"
        return score, why
    if medium_exact:
        score = 6 if medium_exact == 1 else 7 if medium_exact == 2 else 8
        return score, f"{medium_exact} exact-product program match(es)"
    # Only weak CMS-family matches.
    score = clamp(int(3 + 0.2 * family_only + 0.5), lo=3, hi=5)
    return score, (
        f"{family_only} CMS-family match(es) only — program runs the parent "
        "CMS, not confirmation the affected component is deployed"
    )


def score_prevalence(
    product: str,
    description: str,
    pairings: list[dict[str, Any]],
) -> tuple[int, str]:
    pop, pop_why = product_popularity(product, description, pairings)
    sig, sig_why = match_signal(pairings)
    score = round_score(0.60 * pop + 0.40 * sig)
    reason = f"prevalence {score} ({pop_why}; {sig_why})"
    return score, reason


# ---------------------------------------------------------------------------
# Reproduction complexity
# ---------------------------------------------------------------------------

@dataclass
class RepoDoc:
    full_name: str
    url: str
    stars: int
    reachable: bool
    has_readme: bool
    readme: str
    source_url: str | None = None
    error: str | None = None


def poc_sort_key(poc: dict[str, Any]) -> tuple[int, int, int, int]:
    name = (poc.get("full_name") or "").lower()
    stars = int(poc.get("stars") or 0)
    # Prefer real write-ups over thin auto-generated stubs.
    stub = 1 if any(s in name for s in ("cveforge/", "googlesky/", "evenomn/")) else 0
    fork = 1 if poc.get("fork") else 0
    return (stars, 0 if stub == 0 else -1, -fork, len(name))


def readme_urls(full_name: str) -> list[str]:
    name = full_name.strip().strip("/")
    names = ("README.md", "README.MD", "readme.md", "README", "README.rst", "README.txt")
    refs = ("HEAD", "main", "master")
    urls: list[str] = []
    for ref in refs:
        for fn in names:
            urls.append(f"https://raw.githubusercontent.com/{name}/{ref}/{fn}")
    return urls


def fetch_repo_doc(poc: dict[str, Any], cache: dict[str, Any]) -> RepoDoc:
    full_name = (poc.get("full_name") or "").strip()
    url = poc.get("url") or (f"https://github.com/{full_name}" if full_name else "")
    stars = int(poc.get("stars") or 0)
    repos: dict[str, Any] = cache.setdefault("repos", {})
    cached = repos.get(full_name) if full_name else None
    if isinstance(cached, dict) and cached.get("status") in {"ok", "thin", "missing", "unreachable"}:
        return RepoDoc(
            full_name=full_name,
            url=url,
            stars=stars,
            reachable=cached.get("status") in {"ok", "thin", "missing"},
            has_readme=cached.get("status") == "ok" and bool(cached.get("readme")),
            readme=cached.get("readme") or "",
            source_url=cached.get("source_url"),
            error=cached.get("error"),
        )

    doc = RepoDoc(
        full_name=full_name or url or "unknown",
        url=url,
        stars=stars,
        reachable=False,
        has_readme=False,
        readme="",
    )
    if not full_name or "/" not in full_name:
        doc.error = "no github repo name"
        repos[full_name or url or "unknown"] = {
            "status": "unreachable",
            "error": doc.error,
            "readme": "",
        }
        return doc

    readme_body = ""
    source_url = None
    saw_unreach = False
    for raw_url in readme_urls(full_name):
        result = http_get(raw_url)
        if result is None:
            saw_unreach = True
            continue
        status, body = result
        if status == 200 and body.strip():
            readme_body = body
            source_url = raw_url
            break
        if status in {429, 503}:
            time.sleep(1.5)
            continue

    if readme_body.strip():
        doc.reachable = True
        doc.has_readme = True
        doc.readme = readme_body
        doc.source_url = source_url
        status = "ok"
        # Very short READMEs are recorded as thin so scoring leans on the advisory.
        if len(readme_body.strip()) < THIN_README_MAX:
            status = "thin"
            doc.has_readme = True
        repos[full_name] = {
            "status": status,
            "source_url": source_url,
            "readme": readme_body[:60_000],
            "error": None,
        }
        return doc

    # No README found — check whether the repo itself exists.
    api = http_get(
        f"https://api.github.com/repos/{full_name}",
        accept="application/vnd.github+json",
    )
    if api is None:
        html = http_get(f"https://github.com/{full_name}")
        if html is None or html[0] >= 500:
            doc.error = "repo unreachable"
            doc.reachable = False
            repos[full_name] = {"status": "unreachable", "error": doc.error, "readme": ""}
            return doc
        status, _ = html
        if status == 200:
            doc.reachable = True
            doc.error = "no README"
            repos[full_name] = {"status": "missing", "error": doc.error, "readme": ""}
            return doc
        if status == 404:
            doc.error = "repo not found"
            repos[full_name] = {"status": "unreachable", "error": doc.error, "readme": ""}
            return doc
        doc.error = f"repo http {status}"
        repos[full_name] = {"status": "unreachable", "error": doc.error, "readme": ""}
        return doc

    status, body = api
    if status == 200:
        doc.reachable = True
        doc.error = "no README"
        repos[full_name] = {"status": "missing", "error": doc.error, "readme": ""}
        return doc
    if status == 404:
        doc.error = "repo not found"
        repos[full_name] = {"status": "unreachable", "error": doc.error, "readme": ""}
        return doc
    if saw_unreach and status >= 500:
        doc.error = "repo unreachable"
        repos[full_name] = {"status": "unreachable", "error": doc.error, "readme": ""}
        return doc
    # Rate-limited or odd status: treat as unreachable rather than guess high.
    doc.error = f"repo http {status}"
    repos[full_name] = {"status": "unreachable", "error": doc.error, "readme": ""}
    return doc


def fetch_nuclei_text(templates: list[dict[str, Any]], cache: dict[str, Any]) -> str:
    chunks: list[str] = []
    repos: dict[str, Any] = cache.setdefault("repos", {})
    for tpl in templates or []:
        path = (tpl.get("path") or "").lstrip("/")
        if not path or ".." in path:
            continue
        key = f"nuclei:{path}"
        cached = repos.get(key)
        if isinstance(cached, dict):
            if cached.get("readme"):
                chunks.append(cached["readme"])
            continue
        raw_url = (
            "https://raw.githubusercontent.com/projectdiscovery/"
            f"nuclei-templates/main/{path}"
        )
        result = http_get(raw_url)
        if result is None or result[0] != 200 or not result[1].strip():
            repos[key] = {"status": "unreachable", "readme": "", "source_url": raw_url}
            continue
        body = result[1]
        repos[key] = {"status": "ok", "readme": body[:40_000], "source_url": raw_url}
        chunks.append(body)
    return "\n".join(chunks)


def _best_easy_signal(text: str) -> tuple[int, str] | None:
    """Highest easy-signal hit in text, or None."""
    best: tuple[int, str] | None = None
    for score, why, pat in EASY_SIGNALS:
        if pat.search(text or "") and (best is None or score > best[0]):
            best = (score, why)
    return best


def score_reproduction(
    description: str,
    docs: list[RepoDoc],
    nuclei_text: str,
) -> tuple[int | None, str, RepoDoc | None]:
    """Return (score or None if unrated, one-line reason, chosen doc).

    Easy-signal boosts come primarily from the official advisory (and a
    nuclei template, if present). Auto-generated stub READMEs cannot raise
    the score on their own — they often contain generic mermaid diagrams
    or curl examples that do not match the advisory.
    """
    reachable = [d for d in docs if d.reachable]
    if not reachable:
        return None, "unrated, repo unreachable", docs[0] if docs else None

    # Prefer the most documented non-stub repo; fall back to the longest.
    nonstub = [d for d in reachable if not is_stub_doc(d)]
    pool = nonstub or reachable
    chosen = max(
        pool,
        key=lambda d: (len(d.readme.strip()), d.stars, 0 if d.has_readme else -1),
    )
    readme = chosen.readme or ""
    thin = len(readme.strip()) < THIN_README_MAX
    stub = is_stub_doc(chosen)
    advisory = description or ""
    trusted_blob = f"{advisory}\n{nuclei_text or ''}"
    # Non-stub READMEs can contribute easy signals and setup detail.
    readme_for_easy = "" if stub else readme
    full_for_caps = f"{advisory}\n{readme}\n{nuclei_text or ''}"

    cap = 10
    cap_why = ""
    for cap_score, why, pat in HARD_CAPS:
        if pat.search(full_for_caps):
            if cap_score < cap:
                cap = cap_score
                cap_why = why

    if cap >= 6 and re.search(
        r"\b(cwe-119|cwe-122|cwe-125|cwe-415|cwe-416|cwe-787)\b",
        full_for_caps,
        re.I,
    ):
        cap, cap_why = 3, "memory-corruption CWE"

    base = 6
    base_why = "advisory describes the issue but not a one-request trigger"
    adv_easy = _best_easy_signal(advisory)
    if adv_easy:
        base, base_why = adv_easy

    readme_easy = _best_easy_signal(readme_for_easy) if readme_for_easy else None
    # A real write-up may clarify a vague advisory, but cannot invent a
    # copy-paste GET that the advisory does not support, and cannot outrank
    # the advisory by more than one band.
    if readme_easy and readme_easy[0] > base:
        lifted = min(readme_easy[0], max(base, 8), (adv_easy[0] + 1) if adv_easy else 8)
        if lifted > base:
            base, base_why = lifted, readme_easy[1] + " (from PoC write-up)"

    if nuclei_text and cap >= 8 and base < 9:
        if re.search(r"(?m)^(method|path|raw):", nuclei_text):
            base, base_why = 9, "public nuclei template documents an HTTP request"

    # Deserialization cap comes from the advisory, not a related-CVE mention
    # in a PoC README table.
    if DESER_RE.search(advisory) and base > 6:
        base, base_why = 6, "PHP object injection / deserialization (needs a gadget)"
    if (not stub) and COMPILED_RE.search(readme) and cap > 3:
        cap, cap_why = min(cap, 4), (cap_why or "compiled/native exploit in the PoC repo")

    if SINGLE_GET_RE.search(advisory) and cap >= 9:
        base, base_why = 10, "advisory documents a single GET"
    elif (not stub) and SINGLE_GET_RE.search(readme) and cap >= 9 and base >= 8:
        base, base_why = 10, "PoC write-up documents a single GET"

    score = min(base, cap)
    penalties: list[str] = []
    deducted = 0
    for amt, why, pat in SETUP_PENALTIES:
        # Lab-build penalty: ignore boilerplate in stub READMEs, and don't
        # punish an advisory that already documents a simple HTTP trigger
        # just because the writer used Docker as a test harness.
        if "lab build" in why:
            if stub:
                continue
            # A Docker test harness does not make an already-documented
            # HTTP/upload trigger "a lab-only exploit".
            if re.search(
                r"\b(http|request|endpoint|ajax|upload|get request|post request)\b",
                advisory,
                re.I,
            ):
                continue
            if pat.search(readme) or pat.search(full_for_caps):
                deducted += amt
                penalties.append(why)
            continue
        if pat.search(advisory) or (not stub and pat.search(readme)):
            deducted += amt
            penalties.append(why)
    score = clamp(score - deducted)

    if cap < 10 and cap < (base):
        reason = cap_why
        if penalties:
            reason += "; " + ", ".join(penalties)
        reason += f" → {score}"
    else:
        reason = base_why
        if penalties:
            reason += "; " + ", ".join(penalties)
        reason += f" → {score}"
    if stub and thin and chosen.has_readme:
        reason = "thin/stub PoC README, scoring from advisory: " + reason
    elif stub and chosen.has_readme:
        reason = "stub PoC README, scoring from advisory: " + reason
    elif thin and chosen.has_readme:
        reason = "thin PoC README, scoring from advisory: " + reason
    elif not chosen.has_readme:
        reason = "no PoC README, scoring from advisory: " + reason
    return score, reason, chosen



# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass
class Ranked:
    cve_id: str
    nvd_url: str
    product: str
    cvss: Any
    severity: str | None
    privilege_tag: str
    description: str
    combined: int | None
    prevalence: int | None
    reproduction: int | None
    prevalence_reason: str
    reproduction_reason: str
    unrated: bool
    pairings: list[dict[str, Any]]
    poc: dict[str, Any] | None
    nuclei: list[dict[str, Any]]
    bounty_relevant: bool
    web_score: float
    cwes: list[str] = field(default_factory=list)
    poc_trust: str = "unverified"
    poc_trust_tag: str = "unverified"
    poc_trust_reason: str = ""
    credible_poc: bool = False
    desc_confidence: str = "medium"


def feed_index(feed: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in feed.get("items") or []:
        cid = (item.get("cve_id") or "").upper()
        if cid:
            out[cid] = item
    return out


def group_pairings(match: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in match.get("items") or []:
        cid = (item.get("cve_id") or "").upper()
        if not cid:
            continue
        groups.setdefault(cid, []).append(item)
    return groups


def unique_programs(pairings: list[dict[str, Any]]) -> list[tuple[str, str | None, str, str]]:
    """Return unique (name, url, platform, confidence) in first-seen order, best conf kept."""
    rank = {"high": 3, "medium": 2, "low": 1}
    best: dict[str, tuple[str, str | None, str, str]] = {}
    order: list[str] = []
    for p in pairings:
        prog = p.get("program") or {}
        name = prog.get("name") or prog.get("handle") or "unknown program"
        key = f"{prog.get('platform') or ''}:{prog.get('handle') or name}"
        conf = p.get("confidence") or "medium"
        url = prog.get("url")
        platform = prog.get("platform") or ""
        if key not in best:
            best[key] = (name, url, platform, conf)
            order.append(key)
        else:
            old = best[key]
            if rank.get(conf, 0) > rank.get(old[3], 0):
                best[key] = (name, url, platform, conf)
    return [best[k] for k in order]


def product_of(cid: str, feed_item: dict[str, Any] | None, pairings: list[dict[str, Any]]) -> str:
    if pairings and pairings[0].get("product"):
        return str(pairings[0]["product"])
    if feed_item:
        products = feed_item.get("products") or []
        if products and isinstance(products[0], str):
            return products[0]
        if feed_item.get("product"):
            return str(feed_item["product"])
    return "Unknown product"


def gather_pocs(feed_item: dict[str, Any] | None, pairings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pocs: list[dict[str, Any]] = []
    seen: set[str] = set()
    if feed_item:
        for p in feed_item.get("pocs") or []:
            key = (p.get("full_name") or p.get("url") or "").lower()
            if key and key not in seen:
                pocs.append(p)
                seen.add(key)
    for pairing in pairings:
        p = pairing.get("poc")
        if not p:
            continue
        key = (p.get("full_name") or p.get("url") or "").lower()
        if key and key not in seen:
            pocs.append(p)
            seen.add(key)
    pocs.sort(key=poc_sort_key, reverse=True)
    return pocs


def rank_one(
    cid: str,
    feed_item: dict[str, Any] | None,
    pairings: list[dict[str, Any]],
    cache: dict[str, Any],
    budget: "poc_trust.ApiBudget | None" = None,
) -> Ranked:
    product = product_of(cid, feed_item, pairings)
    src = pairings[0] if pairings else (feed_item or {})
    description = (
        (feed_item or {}).get("description")
        or src.get("description")
        or ""
    )
    nvd = (feed_item or {}).get("nvd_url") or src.get("nvd_url") or NVD_DETAIL.format(cve_id=cid)
    tag_src = feed_item or src
    tag = privilege_tag_from_record(tag_src)
    pocs = gather_pocs(feed_item, pairings)
    nuclei = (feed_item or {}).get("nuclei_templates") or []

    prev, prev_why = score_prevalence(product, description, pairings)

    docs = [fetch_repo_doc(p, cache) for p in pocs] if pocs else []
    nuclei_text = fetch_nuclei_text(nuclei, cache) if nuclei else ""
    repro, repro_why, chosen = score_reproduction(description, docs, nuclei_text)

    # --- PoC trustworthiness (offline signals + README + optional contents API) -
    doc_by_name = {d.full_name: d for d in docs}
    poc_ratings: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for pc in pocs:
        doc = doc_by_name.get(pc.get("full_name") or "")
        readme = doc.readme if (doc and doc.reachable and doc.readme) else None
        tr = poc_trust.enrich_rating(
            pc,
            cve_id=cid,
            product=product,
            readme=readme,
            cache=cache,
            budget=budget,
        )
        poc_ratings.append((pc, tr))

    trust_rank = {"trusted": 2, "unverified": 1, "likely-stub": 0}
    best_poc_dict: dict[str, Any] | None = None
    best_tr: dict[str, Any] = {"rating": "unverified", "tag": "unverified", "reason": ""}
    if poc_ratings:
        best_poc_dict, best_tr = max(
            poc_ratings,
            key=lambda x: (trust_rank.get(x[1]["rating"], 0), x[1]["stars"]),
        )
    credible_poc = any(tr["rating"] != "likely-stub" for _, tr in poc_ratings)

    # A stub-only finding has no working public PoC: reproducing it means
    # building the exploit from the advisory, so it must not score as "easy".
    if repro is not None and poc_ratings and not credible_poc and repro > 6:
        repro = 6
        repro_why += "; capped at 6 — only stub/auto-generated PoCs, exploit must be built from the advisory"

    # Prefer the most credible PoC for the displayed link; fall back to chosen.
    display = best_poc_dict
    display_doc = doc_by_name.get((display or {}).get("full_name") or "") if display else None
    poc_out: dict[str, Any] | None = None
    if display is not None:
        poc_out = {
            "full_name": display.get("full_name"),
            "url": display.get("url"),
            "stars": int(display.get("stars") or 0),
            "reachable": bool(display_doc.reachable) if display_doc else False,
            "has_readme": bool(display_doc.has_readme) if display_doc else False,
            "source_url": display_doc.source_url if display_doc else None,
            "trust": best_tr["rating"],
            "trust_tag": best_tr["tag"],
            "trust_reason": best_tr["reason"],
        }
    elif chosen is not None:
        poc_out = {
            "full_name": chosen.full_name,
            "url": chosen.url,
            "stars": chosen.stars,
            "reachable": chosen.reachable,
            "has_readme": chosen.has_readme,
            "source_url": chosen.source_url,
            "trust": best_tr["rating"],
            "trust_tag": best_tr["tag"],
            "trust_reason": best_tr["reason"],
        }

    unrated = repro is None
    combined = None if unrated else round_score(W_REPRO * repro + W_PREV * prev)
    # Stub-only findings lose a point so a credible PoC outranks a stub at a tie.
    if combined is not None and poc_ratings and not credible_poc:
        combined = clamp(combined - 1)

    # Description accuracy / confidence.
    summary, desc_conf = short_bug_summary_conf(description, (feed_item or src).get("cwes"))

    return Ranked(
        cve_id=cid,
        nvd_url=nvd,
        product=product,
        cvss=(feed_item or src).get("cvss"),
        severity=(feed_item or src).get("severity"),
        privilege_tag=tag,
        description=description,
        combined=combined,
        prevalence=None if unrated else prev,
        reproduction=repro,
        prevalence_reason=prev_why,
        reproduction_reason=repro_why,
        unrated=unrated,
        pairings=pairings,
        poc=poc_out,
        nuclei=nuclei,
        bounty_relevant=bool((feed_item or {}).get("bounty_relevant")),
        web_score=float(((feed_item or {}).get("scores") or {}).get("web") or 0),
        cwes=list((feed_item or src).get("cwes") or []),
        poc_trust=best_tr["rating"],
        poc_trust_tag=best_tr["tag"],
        poc_trust_reason=best_tr["reason"],
        credible_poc=credible_poc,
        desc_confidence=desc_conf,
    )


_TRUST_ORDER = {"trusted": 2, "unverified": 1, "likely-stub": 0}


def sort_key(r: Ranked) -> tuple:
    return (
        0 if r.unrated else 1,
        r.combined or 0,
        1 if r.credible_poc else 0,
        _TRUST_ORDER.get(r.poc_trust, 1),
        r.reproduction or 0,
        r.prevalence or 0,
        float(r.cvss or 0),
        r.cve_id,
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

FORMULA_LINES = (
    f"research_priority = clamp(1, 10, round({W_REPRO:.2f} × reproduction_complexity "
    f"+ {W_PREV:.2f} × prevalence))",
    "Reproduction complexity (1-10) is weighted higher so hard-to-reproduce issues rank low even on common products; 10 is a single documented unauthenticated HTTP request with minimal setup.",
    "Prevalence (1-10) = clamp(1, 10, round(0.60 × product_popularity + 0.40 × match_signal)); CMS-family-only program hits count little, first-party/high-confidence exact-product hits count a lot.",
)


def format_programs(pairings: list[dict[str, Any]], *, markdown: bool, limit: int = 6) -> str:
    progs = unique_programs(pairings)
    if not progs:
        return "no program match"
    bits: list[str] = []
    for name, url, platform, conf in progs[:limit]:
        label = f"{name}" + (f" ({platform})" if platform else "")
        if markdown:
            bits.append(f"{md_link(name, url)} ({platform}, {conf})" if platform else md_link(name, url))
        else:
            bits.append(f"{label} ({conf})" + (f" {url}" if url else ""))
    extra = len(progs) - limit
    if extra > 0:
        bits.append(f"+{extra} more")
    return ", ".join(bits)


VENDOR_PREFIXES = (
    r"Apache Software Foundation\s+",
    r"The Apache Software Foundation\s+",
    r"PHP Group\s+",
    r"Joomla!? Project\s+",
    r"Eclipse Foundation\s+",
)

# Bug-class patterns, most specific first. Used only for the compact one-line summary.
_BUG_CLASSES = [
    (r"request smuggling|http smuggling", "HTTP smuggling"),
    (r"desynchroniz|response desync|http desync|pipelined response", "HTTP response desync"),
    (r"arbitrary file deletion|\bfile deletion\b", "file deletion"),
    (r"arbitrary file upload|unrestricted upload|\bfile upload\b", "file upload"),
    (r"path traversal|directory traversal|\btraversal\b|parent-directory|dot-dot|sanitizepathname", "path traversal"),
    (r"local file inclusion|\bLFI\b", "LFI"),
    (r"remote file inclusion|\bRFI\b", "RFI"),
    (r"arbitrary file read|\bfile read\b", "file read"),
    (r"arbitrary file write|\bfile write\b", "file write"),
    (r"sql injection|\bsqli\b|parse as sql|error-based", "SQLi"),
    (r"server-side template|\bstti\b|template injection", "SSTI"),
    (r"server-side request forgery|\bssrf\b", "SSRF"),
    (r"cross-site scripting|\bxss\b", "XSS"),
    (r"xml external entity|\bxxe\b", "XXE"),
    (r"cross-site request forgery|\bcsrf\b", "CSRF"),
    (r"prototype pollution", "prototype pollution"),
    (r"object injection", "object injection"),
    (r"insecure deserialization|deserialization of untrusted|\bdeserializ", "deserialization"),
    (r"command injection|os command|arbitrary command", "command injection"),
    (r"authentication bypass|auth(?:entication)? bypass|missing authentication", "auth bypass"),
    (r"authorization bypass|authz bypass|missing authorization|broken access|improper access control", "access control"),
    (r"privilege escalation|priv(?:ilege)? esc", "privilege escalation"),
    (r"account takeover|take over (?:that |the |an )?(?:administrator )?account|take it over|change the password of any", "account takeover"),
    (r"hard-coded cryptographic key|hardcoded cryptographic key|hard-coded key|hardcoded key|constant salt", "hardcoded key"),
    (r"open redirect", "open redirect"),
    (r"use-after-free|buffer overflow|memory corruption|heap overflow", "memory corruption"),
    (r"remote code execution|remote command execution|arbitrary code|\bRCE\b|execute(?:s|d)?(?: arbitrary)? code", "RCE"),
    (r"code execution", "RCE"),
]

_VECTORS = [
    (r"xml-?rpc", "via XML-RPC"),
    (r"request uri|in the url path|via the url", "via URL"),
    (r"file upload field|via the ['\"]?upload", "via file upload"),
    (r"install(?:ation)? folder|web installer|leftover installer", "via leftover installer"),
    (r"\beval\s*\(", "via eval"),
    (r"double-submit cookie|csrf cookie", "via CSRF cookie"),
    (r"php://input", "via unread request body"),
    (r"\bzip\b|\bphar\b|\barchive\b", "via zip/archive"),
    (r"websocket", "via WebSocket"),
    (r"\bajax\b", "via AJAX"),
    (r"graphql", "via GraphQL"),
    (r"\bjwt\b", "via JWT"),
]

# Classes that already imply code execution, so we don't append "to RCE".
_RCE_KINDS = {
    "RCE",
    "command injection",
    "object injection",
    "deserialization",
    "memory corruption",
}


def poc_short_name(poc: dict[str, Any] | None) -> str:
    """Short repo label for compact output: repo name, or owner/repo if the repo is just a CVE id."""
    poc = poc or {}
    full = (poc.get("full_name") or "").strip()
    if "/" in full:
        _owner, repo = full.split("/", 1)
        if re.match(r"(?i)^cve-\d{4}-\d+", repo) or repo.lower() in {"poc", "exploit", "cve"}:
            return full
        return repo
    if full:
        return full
    url = poc.get("url") or ""
    if url.rstrip("/").split("/")[-1]:
        return url.rstrip("/").split("/")[-1]
    return "PoC"


def short_product(product: str, limit: int = 52) -> str:
    p = " ".join((product or "Unknown product").split())
    for pat in VENDOR_PREFIXES:
        p = re.sub(rf"^{pat}", "", p, flags=re.I).strip()
    # Drop a leading CPE vendor slug like "Saturdaydrive" or "Techlabpro1".
    parts = p.split()
    if len(parts) >= 3:
        tok = parts[0]
        slug = bool(re.search(r"\d", tok)) or (
            tok.isalpha() and len(tok) >= 7 and tok.lower() not in {"wordpress", "woocommerce", "microsoft", "restrictions"}
        )
        if slug:
            p = " ".join(parts[1:])
    return one_line(p, limit)


def _class_from_text(text: str) -> str | None:
    if not text:
        return None
    for pat, label in _BUG_CLASSES:
        if re.search(pat, text, re.I):
            return label
    return None


def _vulnerable_to(text: str) -> str | None:
    """Prefer the advisory's own 'vulnerable to X' clause when present."""
    m = re.search(r"vulnerable to ([^.]{4,80})", text or "", re.I)
    if not m:
        return None
    snippet = re.split(
        r"\s+in all versions|\s+in versions|\s+before\b|\s+when\b|\s+due to\b|\s+via\b",
        m.group(1),
        maxsplit=1,
    )[0].strip()
    mapped = _class_from_text(snippet)
    if mapped == "XSS" and re.search(r"(?i)\bstored\b", snippet):
        return "stored XSS"
    if mapped == "XSS" and re.search(r"(?i)\breflected\b", snippet):
        return "reflected XSS"
    return mapped


def _named_vulnerability(text: str) -> str | None:
    """Pull a short name from 'X vulnerability in …' or 'contains a X vulnerability'."""
    body = re.sub(r"^(?:[^.]+?\bis a\b[^.]*\.)\s*", "", (text or "").strip(), count=1, flags=re.I)
    m = re.search(r"contains (?:a |an )?(.+?) vulnerability", body, flags=re.I)
    if m:
        mapped = _class_from_text(m.group(1)) or _class_from_text(m.group(0))
        if mapped:
            return mapped
        name = " ".join(re.sub(r"\s*\([^)]*\)\s*", " ", m.group(1)).split()).lower()
        if 6 <= len(name) <= 60 and not re.search(r"(?i)\b(version|wordpress|plugin|before)\b", name):
            return name
    m = re.match(r"(.{6,70}?)\s+vulnerability\b", body, flags=re.I)
    if not m:
        return None
    name = m.group(1).strip()
    if re.search(r"(?i)\b(version|affected|through|cve-)\b", name):
        return None
    if name.lower() in {"a", "an", "this", "the"}:
        return None
    mapped = _class_from_text(name)
    if mapped:
        return mapped
    name = re.sub(r"\s*\([^)]*\)\s*", " ", name)
    return " ".join(name.split()).lower() or None


_CWE_LABELS = {
    "CWE-22": "path traversal",
    "CWE-24": "path traversal",
    "CWE-78": "command injection",
    "CWE-79": "XSS",
    "CWE-89": "SQLi",
    "CWE-94": "code injection",
    "CWE-95": "code injection",
    "CWE-98": "file inclusion",
    "CWE-269": "privilege escalation",
    "CWE-284": "access control",
    "CWE-287": "auth bypass",
    "CWE-288": "auth bypass",
    "CWE-306": "auth bypass",
    "CWE-322": "auth bypass",
    "CWE-352": "CSRF",
    "CWE-434": "file upload",
    "CWE-444": "HTTP smuggling",
    "CWE-502": "deserialization",
    "CWE-601": "open redirect",
    "CWE-611": "XXE",
    "CWE-798": "hardcoded key",
    "CWE-862": "access control",
    "CWE-918": "SSRF",
}


def _cwe_kind(cwes: list[str] | None) -> str | None:
    # Prefer the short compact labels; fall back to the shared authoritative map.
    for cwe in cwes or []:
        label = _CWE_LABELS.get(str(cwe).upper())
        if label:
            return label
    return vuln_types.primary_cwe_type(cwes)


def short_bug_summary(description: str, cwes: list[str] | None = None) -> str:
    """Plain, short 'what it is' phrase for the compact list (e.g. 'unauth file upload')."""
    text = description or ""
    low = text.lower()
    kind = _vulnerable_to(text) or _class_from_text(text) or _named_vulnerability(text)
    incomplete = bool(re.search(r"fix for CVE-\d+-\d+ was incomplete|incomplete fix", low, re.I))
    cwe_kind = _cwe_kind(cwes)
    if not kind:
        if incomplete and cwe_kind:
            kind = f"incomplete {cwe_kind} fix"
        elif cwe_kind:
            kind = cwe_kind
        elif incomplete:
            kind = "incomplete patch"
        else:
            kind = "see advisory"

    also_rce = bool(
        re.search(
            r"remote code execution|\bRCE\b|execute(?:s|d)?(?: arbitrary)? code|arbitrary code",
            low,
            re.I,
        )
    )
    if also_rce and kind not in _RCE_KINDS and "rce" not in kind.lower():
        kind = f"{kind} to RCE"

    vector = None
    for pat, label in _VECTORS:
        if re.search(pat, low, re.I):
            vector = label
            break
    if vector and vector.lower().replace("via ", "") in kind.lower():
        vector = None

    unauth = bool(
        re.search(
            r"unauth|pre-auth|without authenticat|no authenticat|missing authentication|unauthenticated",
            low,
            re.I,
        )
    )
    if unauth and "auth" not in kind.lower():
        kind = f"unauth {kind}"

    phrase = f"{kind} {vector}".strip() if vector else kind
    return one_line(phrase, 80)


def short_bug_summary_conf(
    description: str, cwes: list[str] | None = None
) -> tuple[str, str]:
    """Short 'what it is' phrase plus a confidence in how it was derived.

    Confidence is 'high' when both the advisory prose and the authoritative NVD
    CWE point at a bug class, 'medium' when only one does, and 'low' when the
    type could not be confidently derived (the summary then says 'see advisory'
    and the output flags it rather than inventing a description).
    """
    text = description or ""
    text_kind = _vulnerable_to(text) or _class_from_text(text) or _named_vulnerability(text)
    cwe_kind = _cwe_kind(cwes)
    desc_ok = vuln_types.looks_like_real_description(text)
    summary = short_bug_summary(description, cwes)

    low_markers = ("see advisory", "incomplete patch")
    if not desc_ok:
        confidence = "low"
    elif any(m in summary.lower() for m in low_markers):
        confidence = "low"
    elif text_kind and cwe_kind:
        confidence = "high"
    elif text_kind or cwe_kind:
        confidence = "medium"
    else:
        confidence = "low"
    return summary, confidence


def _exact_pairings(pairings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [p for p in pairings if (p.get("match_type") or "exact") == "exact"]


def format_top_program(pairings: list[dict[str, Any]], *, markdown: bool = True) -> str:
    """One representative program plus '+N more'.

    Prefers a confirmed exact-product match; if the CVE only has weaker
    cms-family matches (program just runs the parent CMS) the program is shown
    with a 'possible' qualifier so the headline is not over-stated.
    """
    exact = _exact_pairings(pairings)
    pool = exact or pairings
    progs = unique_programs(pool)
    if not progs:
        return "no match"
    rank = {"high": 3, "medium": 2, "low": 1}
    top = max(range(len(progs)), key=lambda i: (rank.get(progs[i][3], 0), -i))
    name, url, _platform, _conf = progs[top]
    label = md_link(name, url) if markdown else name
    total = len(unique_programs(pairings))
    extra = total - 1
    qualifier = "" if exact else " (possible — runs parent CMS)"
    if extra > 0:
        return f"{label} +{extra} more{qualifier}"
    return f"{label}{qualifier}"


def format_finding_compact(r: Ranked) -> str:
    cve = md_link(r.cve_id, r.nvd_url)
    product = short_product(r.product)
    what = short_bug_summary(r.description, r.cwes)
    if r.desc_confidence == "low":
        what += " (type unverified — see advisory)"
    poc = r.poc or {}
    if poc.get("url"):
        tag = poc.get("trust_tag") or r.poc_trust_tag
        poc_bit = f"PoC: {md_link(poc_short_name(poc), poc.get('url'))} {tag}"
    else:
        poc_bit = "PoC: (none)"
    prog_bit = f"Program: {format_top_program(r.pairings, markdown=True)}"
    score = r.combined if r.combined is not None else "?"
    return f"**{score}/10** — {cve} — {product}: {what} — {poc_bit} — {prog_bit}"


COMPACT_HEADER = (
    "Score 1-10: higher = easier PoC to run + more common software. "
    "Read the PoC before running; test only where authorized."
)


def format_text(
    ranked: list[Ranked],
    unrated: list[Ranked],
    meta: dict[str, Any],
    limit: int,
    min_score: int,
    *,
    verbose: bool = False,
) -> str:
    if verbose:
        return format_text_verbose(ranked, unrated, meta, limit, min_score)
    lines: list[str] = [COMPACT_HEADER, ""]
    shown = [r for r in ranked if (r.combined or 0) >= min_score]
    if limit:
        shown = shown[:limit]
    if not shown:
        lines.append("No findings at this minimum score.")
        lines.append("")
    for r in shown:
        lines.append(format_finding_compact(r))
    if unrated:
        lines.append("")
        lines.append("Unrated (PoC repo unreachable):")
        for r in unrated:
            cve = md_link(r.cve_id, r.nvd_url)
            poc = r.poc or {}
            lines.append(
                f"- {cve} — {short_product(r.product)}: {short_bug_summary(r.description, r.cwes)} — "
                f"PoC: {md_link(poc_short_name(poc), poc.get('url'))} — unrated, repo unreachable"
            )
    return "\n".join(lines).rstrip() + "\n"


def format_text_verbose(
    ranked: list[Ranked],
    unrated: list[Ranked],
    meta: dict[str, Any],
    limit: int,
    min_score: int,
) -> str:
    lines: list[str] = []
    shown = [r for r in ranked if (r.combined or 0) >= min_score]
    if limit:
        shown = shown[:limit]
    lines.append(
        f"Research-priority ranking — last {meta['days']} day(s), "
        f"{meta['priv_level']} CVEs with a public PoC"
    )
    lines.append(
        f"Generated {meta['generated']}  |  "
        f"scored {meta['scored']}  ·  unrated {meta['unrated']}  ·  "
        f"showing {len(shown)}"
        + (f" (min-score {min_score})" if min_score else "")
    )
    lines.append(FORMULA_LINES[0])
    if meta.get("privilege_note"):
        lines.append(meta["privilege_note"])
    lines.append(
        "Read-only triage of already-public disclosures. A high score means "
        "the advisory/PoC is easy to study and the product is commonly in "
        "scope — not that any host is vulnerable. Read the program policy "
        "before testing, and only test where you are authorized. This script "
        "never runs a PoC or contacts a target."
    )
    lines.append("")
    if not shown:
        lines.append("No findings at this minimum score.")
        lines.append("")
    for i, r in enumerate(shown, 1):
        cve = md_link(r.cve_id, r.nvd_url)
        lines.append(
            f"{i}. **{r.combined}/10**  (repro {r.reproduction}, prevalence {r.prevalence})  "
            f"{cve} — {r.product} {cvss_text(r.__dict__)} {r.privilege_tag}"
        )
        lines.append(f"   Programs: {format_programs(r.pairings, markdown=True)}")
        poc = r.poc or {}
        poc_label = poc.get("full_name") or "PoC"
        tag = poc.get("trust_tag") or r.poc_trust_tag
        reason = poc.get("trust_reason") or r.poc_trust_reason
        trust_bit = f"  [{tag}]" + (f" — {reason}" if reason else "")
        lines.append(f"   PoC: {md_link(poc_label, poc.get('url'))}{trust_bit}")
        if r.desc_confidence == "low":
            lines.append("   ⚠ Description type could not be confidently derived — see the advisory.")
        lines.append(f"   Why: {r.reproduction_reason}; {r.prevalence_reason}")
        lines.append("")
    if unrated:
        lines.append("Unrated (PoC repo unreachable)")
        lines.append("--------------------------------")
        for r in unrated:
            cve = md_link(r.cve_id, r.nvd_url)
            poc = r.poc or {}
            lines.append(
                f"- {cve} — {r.product} {cvss_text(r.__dict__)} {r.privilege_tag}  ·  "
                f"{md_link(poc.get('full_name') or 'PoC', poc.get('url'))}  ·  "
                f"unrated, repo unreachable"
            )
        lines.append("")
    lines.append("Scoring notes")
    lines.append("-------------")
    lines.append(FORMULA_LINES[1])
    lines.append(FORMULA_LINES[2])
    return "\n".join(lines).rstrip() + "\n"


def ranked_to_json(r: Ranked) -> dict[str, Any]:
    progs = []
    for name, url, platform, conf in unique_programs(r.pairings):
        progs.append({
            "name": name,
            "url": url,
            "platform": platform,
            "confidence": conf,
        })
    summary, desc_conf = short_bug_summary_conf(r.description, r.cwes)
    has_exact = any((p.get("match_type") or "exact") == "exact" for p in r.pairings)
    return {
        "cve_id": r.cve_id,
        "nvd_url": r.nvd_url,
        "product": r.product,
        "short_description": summary,
        "description_confidence": desc_conf,
        "cvss": r.cvss,
        "severity": r.severity,
        "privilege_tag": r.privilege_tag,
        "research_priority": r.combined,
        "reproduction_complexity": r.reproduction,
        "prevalence": r.prevalence,
        "reproduction_reason": r.reproduction_reason,
        "prevalence_reason": r.prevalence_reason,
        "unrated": r.unrated,
        "poc_trust": r.poc_trust,
        "poc_trust_tag": r.poc_trust_tag,
        "poc_trust_reason": r.poc_trust_reason,
        "credible_poc": r.credible_poc,
        "has_exact_match": has_exact,
        "programs": progs,
        "poc": r.poc,
        "nuclei_templates": r.nuclei,
        "bounty_relevant": r.bounty_relevant,
        "formula": {
            "research_priority": f"clamp(1, 10, round({W_REPRO} * reproduction + {W_PREV} * prevalence))",
            "prevalence": "clamp(1, 10, round(0.60 * product_popularity + 0.40 * match_signal))",
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Rank public CVE-with-PoC findings by research priority "
            "(reproduction complexity + prevalence). Read-only: never "
            "executes a PoC or contacts a target host."
        )
    )
    p.add_argument("--days", type=int, default=14, help="CVE lookback window in days (default: 14).")
    p.add_argument("--json", action="store_true", help="Print JSON instead of markdown.")
    p.add_argument(
        "--min-score",
        type=int,
        default=0,
        dest="min_score",
        help="Drop findings whose combined research-priority is below this (default: 0).",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=12,
        help="Maximum number of ranked findings to print (default: 12). Use 0 for all.",
    )
    p.add_argument(
        "--feed-json",
        type=Path,
        help="Precomputed cve-poc-feed.py --json file. Defaults to the cached state file.",
    )
    p.add_argument(
        "--match-json",
        type=Path,
        help="Precomputed cve-program-match.py --json file. Defaults to the cached state file.",
    )
    p.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        help=(
            "Pipeline data directory for clones and caches "
            "(default: $BOUNTY_PIPELINE_DIR, or this script's directory). "
            "If no Bug Bounty digest cache exists here, this script generates "
            "the feed and matcher data itself."
        ),
    )
    p.add_argument(
        "--state-dir",
        type=Path,
        default=None,
        help="Cache directory (default: <base-dir>/state).",
    )
    p.add_argument(
        "--repo",
        type=Path,
        default=None,
        help="Local bounty-targets-data clone (default: <base-dir>/bounty-targets-data).",
    )
    p.add_argument(
        "--include-unmatched",
        action="store_true",
        help=(
            "Also rank unauthenticated CVEs with a public PoC that have no "
            "program-scope match (prevalence then depends on product prior only)."
        ),
    )
    p.add_argument(
        "--refresh",
        action="store_true",
        help="Re-run the feed and matcher even if cached JSON exists.",
    )
    p.add_argument(
        "--pull",
        action="store_true",
        help=(
            "Update public data clones (PoC-in-GitHub, bounty-targets-data) "
            "when generating missing feed/match data. Implied when the cache "
            "is missing."
        ),
    )
    p.add_argument(
        "--verbose",
        "--detail",
        action="store_true",
        help=(
            "Print the detailed view (sub-scores, justification, CVSS, and all "
            "program matches). Default is a short one-line-per-finding list."
        ),
    )
    p.add_argument(
        "--poc-api-budget",
        type=int,
        default=poc_trust.DEFAULT_API_BUDGET,
        help=(
            "Max GitHub REST contents calls per run for PoC trust enrichment "
            f"(default: {poc_trust.DEFAULT_API_BUDGET}; stays under the 60/hr "
            "unauth cap, honours GITHUB_TOKEN, cached 14 days, degrades to "
            "offline signals when exhausted)."
        ),
    )
    p.add_argument(
        "--no-poc-api",
        action="store_true",
        help="Never call the GitHub API; rate PoCs from offline metadata + "
        "cached READMEs only.",
    )
    add_priv_level_argument(p)
    return p.parse_args(argv)


def resolve_feed(args: argparse.Namespace) -> dict[str, Any]:
    path = args.feed_json or default_feed_path(args.state_dir, args.days, args.priv_level)
    if path.exists() and not args.refresh:
        print(f"Loading feed JSON from {path}", file=sys.stderr)
        feed = load_json_file(path)
        # Re-apply the privilege filter in case the file is a broader cache.
        return filter_feed_payload(feed, args.priv_level)
    print(
        f"No Bug Bounty digest cache at {path}; generating the CVE feed locally.",
        file=sys.stderr,
    )
    cmd = [
        sys.executable,
        str(FEED_SCRIPT),
        "--days",
        str(args.days),
        "--json",
        "--limit",
        "0",
        "--priv-level",
        args.priv_level,
        "--state-dir",
        str(args.state_dir),
    ]
    # Fresh or --refresh runs should update the public PoC index.
    if args.refresh or args.pull or not path.exists():
        cmd.append("--pull")
    feed = run_json(cmd, timeout=1200)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(feed, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote feed JSON to {path}", file=sys.stderr)
    except OSError as exc:
        print(f"Warning: could not cache feed JSON at {path}: {exc}", file=sys.stderr)
    return filter_feed_payload(feed, args.priv_level)


def resolve_match(args: argparse.Namespace, feed_path: Path) -> dict[str, Any]:
    path = args.match_json or default_match_path(args.state_dir, args.days, args.priv_level)
    if path.exists() and not args.refresh:
        print(f"Loading match JSON from {path}", file=sys.stderr)
        return load_json_file(path)
    print(
        f"No program-match cache at {path}; running the matcher locally.",
        file=sys.stderr,
    )
    ensure_bounty_targets(args.repo, pull=bool(args.refresh or args.pull))
    cmd = [
        sys.executable,
        str(MATCH_SCRIPT),
        "--days",
        str(args.days),
        "--json",
        "--feed-json",
        str(feed_path),
        "--repo",
        str(args.repo),
        "--priv-level",
        args.priv_level,
    ]
    match = run_json(cmd, timeout=300)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(match, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote match JSON to {path}", file=sys.stderr)
    except OSError as exc:
        print(f"Warning: could not cache match JSON at {path}: {exc}", file=sys.stderr)
    return match


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.days <= 0:
        die("--days must be a positive integer")
    if args.min_score < 0 or args.min_score > 10:
        die("--min-score must be between 0 and 10")
    if args.limit < 0:
        die("--limit must be >= 0")

    base = resolve_base(args.base_dir)
    if args.base_dir:
        os.environ["BOUNTY_PIPELINE_DIR"] = str(base)
    state_dir = (args.state_dir or (base / "state")).expanduser().resolve()
    args.state_dir = state_dir
    args.repo = (args.repo or (base / "bounty-targets-data")).expanduser().resolve()
    if args.feed_json:
        args.feed_json = args.feed_json.expanduser().resolve()
    if args.match_json:
        args.match_json = args.match_json.expanduser().resolve()
    state_dir.mkdir(parents=True, exist_ok=True)

    feed = resolve_feed(args)
    feed_path = args.feed_json or default_feed_path(state_dir, args.days, args.priv_level)
    # If we just loaded from a default path, keep it; if the feed was freshly
    # written there, the matcher can reuse it.
    if not feed_path.exists():
        # resolve_feed may have used a user path or failed to cache.
        tmp = state_dir / f"cve-poc-feed-{args.days}d.priv-{args.priv_level}.json"
        try:
            tmp.write_text(json.dumps(feed, indent=2) + "\n", encoding="utf-8")
            feed_path = tmp
        except OSError as exc:
            die(f"Could not write feed JSON for the matcher: {exc}")
    match = resolve_match(args, feed_path)

    by_feed = feed_index(feed)
    by_match = group_pairings(match)

    cve_ids = list(by_match.keys())
    if args.include_unmatched:
        for cid in by_feed:
            if cid not in by_match:
                cve_ids.append(cid)
    # Preserve matcher order (already ranked) then unmatched feed order.
    # Scoring will re-sort.

    cache_path = state_dir / CACHE_NAME
    cache = load_cache(cache_path)
    budget = poc_trust.ApiBudget(
        limit=0 if args.no_poc_api else args.poc_api_budget,
        enabled=not args.no_poc_api,
    )

    ranked_all: list[Ranked] = []
    print(f"Scoring {len(cve_ids)} finding(s); fetching public PoC READMEs as needed…", file=sys.stderr)
    try:
        for i, cid in enumerate(cve_ids, 1):
            if i % 10 == 0 or i == 1:
                print(f"  {i}/{len(cve_ids)} {cid}", file=sys.stderr)
            ranked_all.append(rank_one(cid, by_feed.get(cid), by_match.get(cid) or [], cache, budget))
    finally:
        try:
            save_cache(cache_path, cache)
        except OSError as exc:
            print(f"Warning: could not write README cache to {cache_path}: {exc}", file=sys.stderr)

    if budget.used or budget.disabled_reason:
        note = f"GitHub contents API: {budget.used} call(s) used"
        if budget.disabled_reason:
            note += f"; stopped ({budget.disabled_reason})"
        print(note, file=sys.stderr)

    unrated = [r for r in ranked_all if r.unrated]
    ranked = [r for r in ranked_all if not r.unrated]
    ranked.sort(key=sort_key, reverse=True)
    unrated.sort(key=lambda r: r.cve_id)

    generated = now_et()
    privilege_note = (
        feed.get("privilege_note")
        or match.get("privilege_note")
        or (
            filter_note(feed.get("privilege_counts") or {}, args.priv_level)
            if feed.get("privilege_counts")
            else None
        )
    )
    meta = {
        "days": args.days,
        "generated": fmt_et(generated),
        "priv_level": args.priv_level,
        "scored": len(ranked),
        "unrated": len(unrated),
        "privilege_note": privilege_note,
        "include_unmatched": bool(args.include_unmatched),
        "cves_in_feed": len(by_feed),
        "cves_with_match": len(by_match),
    }

    if args.json:
        shown = [r for r in ranked if (r.combined or 0) >= args.min_score]
        if args.limit:
            shown = shown[: args.limit]
        json.dump(
            {
                "generated_at": generated.isoformat(),
                "timezone": "America/New_York",
                "window_days": args.days,
                "priv_level": args.priv_level,
                "min_score": args.min_score,
                "include_unmatched": bool(args.include_unmatched),
                "privilege_note": privilege_note,
                "formula": {
                    "research_priority": FORMULA_LINES[0],
                    "weights": {"reproduction_complexity": W_REPRO, "prevalence": W_PREV},
                    "prevalence": "clamp(1, 10, round(0.60 * product_popularity + 0.40 * match_signal))",
                    "notes": FORMULA_LINES[1:],
                },
                "cves_in_feed": len(by_feed),
                "cves_with_match": len(by_match),
                "scored": len(ranked),
                "unrated_count": len(unrated),
                "items": [ranked_to_json(r) for r in shown],
                "unrated": [ranked_to_json(r) for r in unrated],
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        sys.stdout.write(
            format_text(
                ranked,
                unrated,
                meta,
                args.limit,
                args.min_score,
                verbose=args.verbose,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
