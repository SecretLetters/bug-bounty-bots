#!/usr/bin/env python3
"""Shared PoC trustworthiness signals for the bug-bounty pipeline.

Read-only. Rates a public GitHub proof-of-concept repo as

    trusted / unverified / likely-stub

so the feed, matcher, and ranker can prefer a credible PoC and visibly flag the
thin, auto-generated 0-star repos that cheap CVE-mirroring accounts push out.

Signal sources, cheapest first:

  1. The harvested PoC-in-GitHub metadata the feed already carries
     (stargazers_count, created_at, pushed_at, repo description, owner).
     This is GitHub REST data, snapshotted nightly by nomi-sec/PoC-in-GitHub,
     so most signals cost zero live requests.
  2. The repo README text (fetched elsewhere via raw.githubusercontent.com — a
     CDN that is NOT subject to the 60 req/hr REST limit).
  3. OPTIONALLY one GitHub REST "contents" listing per repo to confirm real
     exploit files vs a stub that is only a README naming the CVE. This path is
     cached (14-day TTL) and hard budget-capped per run, honours GITHUB_TOKEN
     when present, backs off permanently on the first HTTP 403 / rate-limit, and
     silently degrades to the offline signals when unavailable.

This module never clones, downloads, builds, or executes any PoC, and never
contacts a bounty target host — only public github.com / api.github.com.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

USER_AGENT = (
    "bounty-pipeline-poc-trust/1.0 "
    "(read-only public metadata; does not execute PoCs or scan hosts)"
)

# Accounts that auto-create one repo per CVE (a README restating the advisory,
# usually 0 stars, no working exploit). Lower-cased owner logins.
KNOWN_BULK_OWNERS = {
    "cveforge", "googlesky", "evenomn", "nukedz", "whitfieldsdad",
    "fnmsd", "hoangductm", "n3rada", "cvefeed", "cve-feed", "cvewatch",
    "cve-vuln", "cveprojectdb", "0xmarcio", "febinrev", "cybersecurityup",
    "karthik-hr0", "lliru", "cyberskote", "cveautomation",
}

# README boilerplate used by the bulk generators (banner badges, author tags).
STUB_README_HINTS = (
    "capsule-render.vercel.app",
    "badge/author-cveforge",
    "badge/author-googlesky",
    "img.shields.io/badge/cve-",
    "readme-typing-svg",
)

# File extensions / names that indicate a real exploit / PoC payload.
CODE_EXT = (
    ".py", ".sh", ".rb", ".js", ".ts", ".go", ".php", ".pl", ".ps1",
    ".c", ".cpp", ".cc", ".java", ".rs", ".ex", ".exs", ".yaml", ".yml",
    ".http", ".jsp", ".aspx", ".nse", ".raw",
)
CODE_FILENAMES = (
    "exploit", "poc", "payload", "requirements.txt", "dockerfile",
    "docker-compose", "makefile", "cargo.toml", "go.mod", "package.json",
    "pom.xml", "setup.py",
)

THIN_README_MAX = 280          # below this, a README is "thin"
TRUSTED_STARS = 5              # stars alone enough to trust (with CVE ref)
CONTENTS_TTL_SECONDS = 14 * 86400
DEFAULT_API_BUDGET = 40        # stay well under 60/hr unauth; token raises cap

RATINGS = ("trusted", "unverified", "likely-stub")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def owner_of(full_name: str) -> str:
    return (full_name or "").split("/", 1)[0].strip().lower()


def repo_of(full_name: str) -> str:
    fn = (full_name or "").strip().strip("/")
    return fn.split("/", 1)[1] if "/" in fn else fn


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


def _product_tokens(product: str) -> list[str]:
    """Meaningful product tokens for a loose 'README references the product' check."""
    stop = {
        "the", "and", "for", "plugin", "theme", "wordpress", "woocommerce",
        "joomla", "drupal", "cms", "core", "server", "project", "inc", "llc",
        "software", "foundation", "apache", "ltd", "group", "app", "system",
    }
    toks = [t for t in _norm(product).split() if len(t) >= 3 and t not in stop]
    return toks


# ---------------------------------------------------------------------------
# offline signal extraction
# ---------------------------------------------------------------------------

@dataclass
class TrustSignals:
    full_name: str
    stars: int = 0
    owner: str = ""
    bulk_owner: bool = False
    created_at: str | None = None
    pushed_at: str | None = None
    single_commit: bool = False          # created ≈ pushed, never iterated
    repo_description: str = ""
    refs_cve: bool = False
    refs_product: bool = False
    readme_len: int | None = None        # None = README not inspected
    readme_stub_markers: bool = False
    real_code: bool | None = None        # None = unknown (no contents/README cue)
    contents_source: str = "offline"     # offline | readme | api
    extras: dict[str, Any] = field(default_factory=dict)


def offline_signals(
    poc: dict[str, Any],
    cve_id: str | None = None,
    product: str | None = None,
) -> TrustSignals:
    """Signals computable from the harvested PoC-in-GitHub record alone."""
    full_name = (poc.get("full_name") or "").strip()
    stars = int(poc.get("stars") or poc.get("stargazers_count") or 0)
    owner = owner_of(full_name)
    desc = poc.get("description") or ""
    created = poc.get("created_at")
    pushed = poc.get("pushed_at")

    sig = TrustSignals(
        full_name=full_name,
        stars=stars,
        owner=owner,
        bulk_owner=owner in KNOWN_BULK_OWNERS,
        created_at=created,
        pushed_at=pushed,
        repo_description=desc,
    )

    cdt, pdt = _parse_iso(created), _parse_iso(pushed)
    if cdt and pdt:
        sig.single_commit = abs((pdt - cdt).total_seconds()) <= 180 and stars == 0

    blob = f"{full_name} {desc}".lower()
    if cve_id:
        sig.refs_cve = cve_id.lower() in blob
    if product:
        toks = _product_tokens(product)
        sig.refs_product = any(t in blob for t in toks) if toks else False
    return sig


def apply_readme(sig: TrustSignals, readme: str | None) -> None:
    """Fold README text (from raw.githubusercontent.com) into the signals."""
    if readme is None:
        return
    body = readme or ""
    sig.readme_len = len(body.strip())
    low = body.lower()
    sig.readme_stub_markers = any(h in low for h in STUB_README_HINTS)
    if not sig.refs_cve and sig.extras.get("cve_id"):
        sig.refs_cve = sig.extras["cve_id"].lower() in low
    # README is substantial and shows a real request/code block -> real code cue.
    has_block = bool(
        re.search(r"```", body)
        or re.search(r"(?mi)^(GET|POST|PUT|PATCH|DELETE)\s+/", body)
        or re.search(r"\bcurl\s+-|requests\.(get|post)\(|http\.client|import\s+requests", body)
    )
    if sig.real_code is None:
        if has_block and sig.readme_len and sig.readme_len >= THIN_README_MAX:
            sig.real_code = True
        elif sig.readme_len is not None and sig.readme_len < THIN_README_MAX and not has_block:
            sig.real_code = False
    sig.contents_source = "readme" if sig.contents_source == "offline" else sig.contents_source


def apply_contents(sig: TrustSignals, filenames: list[str] | None) -> None:
    """Fold a GitHub contents listing into the signals (authoritative real-code)."""
    if filenames is None:
        return
    names = [str(n).lower() for n in filenames]
    code = any(
        n.endswith(CODE_EXT) or any(k in n for k in CODE_FILENAMES)
        for n in names
    )
    # Only a README / LICENSE / images -> stub.
    sig.real_code = bool(code)
    sig.contents_source = "api"
    sig.extras["file_count"] = len(names)


# ---------------------------------------------------------------------------
# rating
# ---------------------------------------------------------------------------

def rate(sig: TrustSignals) -> dict[str, Any]:
    """Collapse signals into {rating, reason, tag, stars, signals}."""
    stars = sig.stars
    reasons: list[str] = []

    # --- likely-stub -------------------------------------------------------
    stub = False
    if sig.bulk_owner:
        stub = True
        reasons.append(f"bulk-generated namespace ({_pretty_owner(sig)})")
    elif sig.readme_stub_markers:
        stub = True
        reasons.append("auto-generated stub README")
    elif sig.real_code is False and stars == 0:
        stub = True
        reasons.append("README restates the CVE, no exploit code")
    elif (
        sig.real_code is None
        and stars == 0
        and sig.single_commit
        and (sig.readme_len is not None and sig.readme_len < THIN_README_MAX)
        and not sig.refs_product
    ):
        stub = True
        reasons.append("thin single-commit repo, no exploit code")

    if stub:
        rating = "likely-stub"
        reason = "; ".join(reasons) or "stub PoC"
        return _package(rating, reason, stars, sig)

    # --- trusted -----------------------------------------------------------
    trusted = False
    if stars >= TRUSTED_STARS and (sig.refs_cve or sig.refs_product):
        trusted = True
        reasons.append(f"★{stars}, references the CVE/product")
    elif sig.real_code and sig.refs_cve and sig.refs_product and (
        stars >= 1 or (sig.readme_len or 0) >= 1000
    ):
        trusted = True
        bits = "real exploit code, references CVE + product"
        reasons.append(f"★{stars}, {bits}" if stars else bits)

    if trusted:
        return _package("trusted", "; ".join(reasons), stars, sig)

    # --- unverified (everything else) -------------------------------------
    if sig.real_code:
        reasons.append(f"★{stars}, real code but unconfirmed authorship")
    elif sig.real_code is None:
        reasons.append(f"★{stars}, not yet inspected — verify before use")
    else:
        reasons.append(f"★{stars}, unverified")
    return _package("unverified", "; ".join(reasons), stars, sig)


def _pretty_owner(sig: TrustSignals) -> str:
    raw = (sig.full_name or "").split("/", 1)[0]
    return raw or sig.owner


def _package(rating: str, reason: str, stars: int, sig: TrustSignals) -> dict[str, Any]:
    return {
        "rating": rating,
        "reason": reason,
        "tag": short_tag(rating, stars),
        "stars": stars,
        "signals": {
            "bulk_owner": sig.bulk_owner,
            "single_commit": sig.single_commit,
            "refs_cve": sig.refs_cve,
            "refs_product": sig.refs_product,
            "readme_len": sig.readme_len,
            "readme_stub_markers": sig.readme_stub_markers,
            "real_code": sig.real_code,
            "source": sig.contents_source,
        },
    }


def short_tag(rating: str, stars: int) -> str:
    """Compact badge for a one-line finding, e.g. '★12 trusted' / '0★ stub, verify'."""
    s = f"★{stars}" if stars else "0★"
    if rating == "trusted":
        return f"{s} trusted"
    if rating == "likely-stub":
        return f"{s} stub, verify"
    return f"{s} unverified"


# Numeric weight (0..1) for scoring: credible PoCs count, stubs are discounted.
TRUST_WEIGHT = {"trusted": 1.0, "unverified": 0.6, "likely-stub": 0.25}


def trust_weight(rating: str | None) -> float:
    return TRUST_WEIGHT.get(rating or "unverified", 0.6)


# ---------------------------------------------------------------------------
# convenience: fully offline rating (feed uses this; no network at all)
# ---------------------------------------------------------------------------

def rate_offline(
    poc: dict[str, Any],
    cve_id: str | None = None,
    product: str | None = None,
) -> dict[str, Any]:
    sig = offline_signals(poc, cve_id, product)
    return rate(sig)


# ---------------------------------------------------------------------------
# optional GitHub REST contents listing (budget + cache + graceful degrade)
# ---------------------------------------------------------------------------

class ApiBudget:
    """Per-run cap on live GitHub REST calls; disables itself on rate-limit."""

    def __init__(self, limit: int = DEFAULT_API_BUDGET, enabled: bool = True) -> None:
        self.remaining = max(0, int(limit))
        self.enabled = enabled and self.remaining > 0
        self.disabled_reason: str | None = None
        self.used = 0

    def can_spend(self) -> bool:
        return self.enabled and self.remaining > 0

    def spend(self) -> None:
        self.remaining -= 1
        self.used += 1
        if self.remaining <= 0:
            self.enabled = False
            self.disabled_reason = self.disabled_reason or "budget exhausted"

    def kill(self, reason: str) -> None:
        self.enabled = False
        self.disabled_reason = reason


def _github_headers() -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_contents(
    full_name: str,
    cache: dict[str, Any],
    budget: ApiBudget,
    *,
    timeout: int = 12,
    now: datetime | None = None,
) -> list[str] | None:
    """Root-level filenames for a repo, cached. None when unavailable.

    Uses one GET /repos/{owner}/{repo}/contents call, counted against `budget`.
    On HTTP 403 (rate limit) the whole budget is killed for the run.
    """
    if not full_name or "/" not in full_name:
        return None
    now = now or datetime.now(timezone.utc)
    repos: dict[str, Any] = cache.setdefault("repos", {})
    entry = repos.setdefault(full_name, {})

    cached = entry.get("contents")
    fetched = _parse_iso(entry.get("contents_fetched_at"))
    if cached is not None and fetched and (now - fetched).total_seconds() < CONTENTS_TTL_SECONDS:
        return list(cached)

    if not budget.can_spend():
        return list(cached) if cached is not None else None

    url = f"https://api.github.com/repos/{full_name}/contents"
    req = urllib.request.Request(url, headers=_github_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            budget.spend()
            raw = resp.read(200_000)
            data = json.loads(raw.decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        budget.spend()
        if exc.code in (403, 429):
            budget.kill(f"github rate limit (HTTP {exc.code})")
            return list(cached) if cached is not None else None
        if exc.code == 404:
            entry["contents"] = []
            entry["contents_fetched_at"] = now.isoformat()
            return []
        return list(cached) if cached is not None else None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return list(cached) if cached is not None else None

    names: list[str] = []
    if isinstance(data, list):
        for it in data:
            if isinstance(it, dict) and it.get("type") == "file" and it.get("name"):
                names.append(str(it["name"]))
            elif isinstance(it, dict) and it.get("type") == "dir" and it.get("name"):
                names.append(str(it["name"]) + "/")
    entry["contents"] = names
    entry["contents_fetched_at"] = now.isoformat()
    return names


def enrich_rating(
    poc: dict[str, Any],
    *,
    cve_id: str | None = None,
    product: str | None = None,
    readme: str | None = None,
    cache: dict[str, Any] | None = None,
    budget: ApiBudget | None = None,
) -> dict[str, Any]:
    """Full rating using offline signals + README + (optional) contents API."""
    sig = offline_signals(poc, cve_id, product)
    sig.extras["cve_id"] = cve_id
    apply_readme(sig, readme)
    if cache is not None and budget is not None and budget.can_spend():
        # Only spend an API call when the cheap signals are inconclusive.
        inconclusive = sig.real_code is None and not sig.bulk_owner and not sig.readme_stub_markers
        if inconclusive:
            names = fetch_contents(sig.full_name, cache, budget)
            apply_contents(sig, names)
    return rate(sig)
