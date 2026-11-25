#!/usr/bin/env python3
"""Daily bug bounty digest — one report from the full pipeline.

Runs watch.py (new programs and scope/payout changes), cve-poc-feed.py
(recent CVEs with public GitHub PoCs), and cve-program-match.py (CVE →
program scope pairings), then prints a single sectioned markdown report.

This script only aggregates public metadata. It does not scan, probe, or
test any host, and it does not download or run proof-of-concept code.

Examples:
  python3 daily-digest.py
  python3 daily-digest.py --no-pull
  python3 daily-digest.py --hours 24 --days 14 --json
  python3 daily-digest.py --priv-level unauth
  python3 daily-digest.py --priv-level all
"""

from __future__ import annotations

import argparse
import os
import json
import subprocess
import sys
from datetime import datetime, timezone
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
from paths import (  # noqa: E402
    SCRIPT_DIR,
    bounty_targets_repo,
    ensure_bounty_targets,
    resolve_base,
    state_dir as default_state_dir,
)


# Scripts always live next to this file. Data (clones, caches) uses the
# configurable base dir ($BOUNTY_PIPELINE_DIR or the script directory).
WATCH_SCRIPT = SCRIPT_DIR / "watch.py"
FEED_SCRIPT = SCRIPT_DIR / "cve-poc-feed.py"
MATCH_SCRIPT = SCRIPT_DIR / "cve-program-match.py"
DEFAULT_REPO = bounty_targets_repo()
DEFAULT_STATE_DIR = default_state_dir()

ET = ZoneInfo("America/New_York")
DEFAULT_HOURS_WEEKDAY = 24
DEFAULT_HOURS_MONDAY = 72
DEFAULT_CVE_DAYS = 14
DEFAULT_UNMATCHED_LIMIT = 8
TARGET_LIST_LIMIT = 20

CAVEATS = (
    "A match means the program's public scope text indicates it runs that "
    "product — not that a given instance is vulnerable, in scope, or on the "
    "affected version. Read the program policy before testing, and only test "
    "where you are authorized. Community PoCs are unverified; read any PoC "
    "(especially thin 0-star repos) before running it, and never run exploit "
    "code against a live target that is out of scope or unauthorized."
)


def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def now_et() -> datetime:
    return datetime.now(ET)


def weekday_hours(now: datetime | None = None) -> int:
    """24h on most days; 72h Monday catch-up for the weekend, in ET."""
    dt = now or now_et()
    return DEFAULT_HOURS_MONDAY if dt.weekday() == 0 else DEFAULT_HOURS_WEEKDAY


def parse_dt(value: str | None) -> datetime | None:
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


def fmt_et(dt: datetime | None, *, with_weekday: bool = False) -> str:
    if dt is None:
        return "unknown"
    et = dt.astimezone(ET)
    if with_weekday:
        # e.g. "Wednesday, Nov 25, 2026, 12:15 PM ET"
        return et.strftime("%A, %b %-d, %Y, %-I:%M %p ET")
    return et.strftime("%Y-%m-%d %H:%M ET")


def one_line(text: str, limit: int = 200) -> str:
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


def product_label(item: dict[str, Any]) -> str:
    products = item.get("products") or []
    if isinstance(products, list) and products:
        first = products[0]
        if isinstance(first, str) and first.strip():
            return first.strip()
        if isinstance(first, dict):
            vendor = (first.get("vendor") or "").strip()
            product = (first.get("product") or "").strip()
            return " ".join(p for p in (vendor, product) if p) or "Unknown product"
    label = item.get("product")
    if isinstance(label, str) and label.strip():
        return label.strip()
    return "Unknown product"


def cvss_text(item: dict[str, Any]) -> str:
    cvss = item.get("cvss")
    if cvss is None:
        return item.get("severity") or "N/A"
    try:
        return f"{float(cvss):.1f}"
    except (TypeError, ValueError):
        return str(cvss)


def best_poc(pocs: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    if not pocs:
        return None
    return max(pocs, key=lambda p: int(p.get("stars") or 0))


def poc_bit(poc: dict[str, Any] | None, *, cve_id: str | None = None, product: str | None = None) -> str:
    if not poc:
        return "PoC: (none listed)"
    name = poc.get("full_name") or "PoC"
    url = poc.get("url")
    # Prefer a precomputed trust tag; else derive one from offline signals.
    tag = poc.get("poc_trust_tag") or poc.get("trust_tag")
    if not tag:
        try:
            tag = poc_trust.rate_offline(poc, cve_id, product)["tag"]
        except Exception:
            tag = None
    if tag:
        return f"PoC: {md_link(name, url)} {tag}"
    return f"PoC: {md_link(name, url)}"


def payout_line(hit: dict[str, Any]) -> str:
    # watch.py JSON uses min_payout / max_payout display strings.
    mn = hit.get("min_payout") or hit.get("min_display")
    mx = hit.get("max_payout") or hit.get("max_display")
    currency = hit.get("currency")
    suffix = ""
    if (mn or mx) and not currency:
        suffix = " (currency not in dataset)"
    if mn and mx:
        return f"min {mn} / max {mx}{suffix}"
    if mx and not mn:
        return f"min unknown / max {mx}{suffix}"
    if mn and not mx:
        return f"min {mn} / max unknown{suffix}"
    if hit.get("offers_bounties"):
        return "min unknown / max unknown (offers bounties; amounts not in dataset)"
    return "no bounty / VDP"


def change_payout_line(ch: dict[str, Any], side: str) -> str:
    # bounty_changes JSON already has preformatted "old" / "new" strings.
    pre = ch.get(side)
    if isinstance(pre, str) and pre.strip():
        return pre
    return payout_line(
        {
            "min_payout": ch.get(f"{side}_min"),
            "max_payout": ch.get(f"{side}_max"),
            "currency": ch.get("currency"),
        }
    )


def git_pull(repo: Path) -> None:
    ensure_bounty_targets(repo, pull=True)


def run_json(cmd: list[str], *, timeout: int, allow_empty_watch: bool = False) -> dict[str, Any]:
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
        if allow_empty_watch and (
            "Baseline and HEAD are the same commit" in err
            or "widen the window" in err.lower()
        ):
            print(
                "watch.py reported no new commits in this window; "
                "section A will be empty.",
                file=sys.stderr,
            )
            return {
                "window": {},
                "new_programs": [],
                "returning_programs": [],
                "scope_additions": [],
                "bounty_changes": [],
                "counts": {},
                "empty_reason": "No commits in this window (baseline and HEAD are the same).",
            }
        die(f"{cmd[1] if len(cmd) > 1 else cmd[0]} exited {proc.returncode}")

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        die(f"{cmd[1] if len(cmd) > 1 else cmd[0]} did not return JSON: {exc}")
    if not isinstance(payload, dict):
        die(f"{cmd[1] if len(cmd) > 1 else cmd[0]} returned JSON that is not an object")
    return payload


def render_targets(targets: list[dict[str, Any]], limit: int = TARGET_LIST_LIMIT) -> list[str]:
    lines: list[str] = []
    shown = targets[:limit]
    for t in shown:
        ident = (t.get("id") or t.get("identifier") or "").strip() or "(unnamed)"
        typ = t.get("type") or t.get("typ") or ""
        typ_bit = f" ({typ})" if typ else ""
        flag = " [WILDCARD]" if t.get("wildcard") else ""
        lines.append(f"  - `{ident}`{typ_bit}{flag}")
    if len(targets) > limit:
        lines.append(f"  - … +{len(targets) - limit} more")
    return lines


def render_program_block(hit: dict[str, Any], asset_label: str) -> list[str]:
    name = hit.get("name") or "(unnamed program)"
    platform = hit.get("platform") or "unknown platform"
    url = hit.get("url")
    lines = [f"- **{md_link(name, url)}** [{platform}]"]
    lines.append(f"  {payout_line(hit)}")
    first_seen = parse_dt(hit.get("first_seen"))
    if first_seen:
        lines.append(f"  First seen in dump: {fmt_et(first_seen)}")
    targets = hit.get("targets") or []
    wild = hit.get("wildcard_count")
    if wild is None:
        wild = sum(1 for t in targets if t.get("wildcard"))
    if targets:
        lines.append(
            f"  {asset_label} ({len(targets)}, {wild} wildcard):"
        )
        lines.extend(render_targets(targets))
    return lines


def render_section_a(watch: dict[str, Any], hours: float, monday_auto: bool) -> str:
    lines: list[str] = []
    lines.append("## A. New programs & scope changes")
    window = watch.get("window") or {}
    baseline = parse_dt(window.get("baseline_time"))
    head = parse_dt(window.get("head_time"))
    hours_bit = f"{hours:g}h"
    if monday_auto and int(hours) == DEFAULT_HOURS_MONDAY:
        hours_bit += " (Monday weekend catch-up)"
    if baseline or head:
        lines.append(
            f"Window: {fmt_et(baseline)} → {fmt_et(head)}  ·  lookback {hours_bit}"
        )
    else:
        lines.append(f"Window: last {hours_bit}")
    lines.append(
        "Filters: VDPs / no-bounty excluded · max payout under $100 excluded "
        "(unknown max kept if the program offers bounties). Wildcards flagged "
        "with `[WILDCARD]`."
    )
    if watch.get("empty_reason"):
        lines.append("")
        lines.append(watch["empty_reason"])
        lines.append("")
        return "\n".join(lines)

    new_programs = watch.get("new_programs") or []
    returning = watch.get("returning_programs") or []
    scope = watch.get("scope_additions") or []
    changes = watch.get("bounty_changes") or []

    lines.append("")
    lines.append(f"### New bounty programs ({len(new_programs)})")
    if not new_programs:
        lines.append("None after filters.")
    else:
        for hit in new_programs:
            lines.extend(render_program_block(hit, "In-scope listed"))
    lines.append("")

    lines.append(f"### Returning / reappeared programs ({len(returning)})")
    if not returning:
        lines.append("None after filters.")
    else:
        for hit in returning:
            lines.extend(render_program_block(hit, "In-scope listed"))
    lines.append("")

    lines.append(f"### Scope additions on existing programs ({len(scope)})")
    if not scope:
        lines.append("None after filters.")
    else:
        for hit in scope:
            lines.extend(render_program_block(hit, "Added assets"))
    lines.append("")

    lines.append(f"### Bounty amount changes ({len(changes)})")
    if not changes:
        lines.append("None detected in dataset payout fields.")
    else:
        for ch in changes:
            name = ch.get("name") or "(unnamed program)"
            platform = ch.get("platform") or "unknown platform"
            url = ch.get("url")
            direction = ""
            old_max, new_max = ch.get("old_max"), ch.get("new_max")
            try:
                if old_max is not None and new_max is not None:
                    if float(new_max) > float(old_max):
                        direction = " — INCREASE"
                    elif float(new_max) < float(old_max):
                        direction = " — DECREASE"
            except (TypeError, ValueError):
                pass
            lines.append(f"- **{md_link(name, url)}** [{platform}]{direction}")
            lines.append(
                f"  {change_payout_line(ch, 'old')} → {change_payout_line(ch, 'new')}"
            )
    lines.append("")

    counts = watch.get("counts") or {}
    skipped = counts.get("skipped_low_payout_or_vdp") or {}
    if skipped:
        lines.append(
            "Skipped as VDP / below max-payout floor: "
            f"{skipped.get('new', 0)} programs that appeared in the window, "
            f"and {skipped.get('scope_programs', 0)} programs already in the "
            "directory (those were not checked for scope additions)."
        )
        lines.append("")
    return "\n".join(lines)


def group_matches(items: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Keep matcher rank order, grouping later pairings under the first CVE hit."""
    groups: list[list[dict[str, Any]]] = []
    index: dict[str, int] = {}
    for it in items:
        cve_id = (it.get("cve_id") or "CVE-unknown").upper()
        if cve_id in index:
            groups[index[cve_id]].append(it)
        else:
            index[cve_id] = len(groups)
            groups.append([it])
    return groups


def pairing_program_line(it: dict[str, Any]) -> str:
    prog = it.get("program") or {}
    prog_name = prog.get("name") or "(unnamed program)"
    prog_url = prog.get("url")
    platform = prog.get("platform") or "unknown platform"
    wild = " [WILDCARD]" if it.get("wildcard") or (
        (it.get("matched_asset") or {}).get("wildcard")
    ) else ""
    conf = it.get("confidence") or "unknown"
    asset = it.get("matched_asset") or {}
    bits = [
        f"→ {md_link(prog_name, prog_url)} ({platform}){wild} [{conf}]"
    ]
    if asset.get("identifier"):
        typ = asset.get("type") or "asset"
        ident = str(asset["identifier"]).replace("`", "'")
        flag = " [WILDCARD]" if asset.get("wildcard") else ""
        bits.append(f"matched asset ({typ}): `{ident}`{flag}")
    if it.get("reason"):
        bits.append(it["reason"])
    return "  ·  ".join(bits)


def render_section_b(match: dict[str, Any], days: int) -> str:
    lines: list[str] = []
    items = match.get("items") or []
    cves_matched = match.get("cves_with_match")
    if cves_matched is None:
        cves_matched = len({it.get("cve_id") for it in items if it.get("cve_id")})
    lines.append("## B. Today's CVE→program matches")
    lines.append(
        f"CVEs with a public PoC in the last {days} day(s), matched to public "
        "program scopes (HackerOne, Bugcrowd, Intigriti, YesWeHack). "
        f"{cves_matched} CVE(s) with ≥1 match · {len(items)} pairing(s) · "
        "min confidence: medium · VDPs / sub-$100 max excluded. "
        "Grouped by CVE (strongest first); every pairing is listed."
    )
    lines.append("")
    if not items:
        lines.append("No CVE→program matches at the default confidence threshold.")
        lines.append("")
        return "\n".join(lines)

    def group_is_exact(group: list[dict[str, Any]]) -> bool:
        return any((g.get("match_type") or "exact") == "exact" for g in group)

    def render_group(i: int, group: list[dict[str, Any]]) -> None:
        it = group[0]
        cve_id = it.get("cve_id") or "CVE-unknown"
        nvd = it.get("nvd_url")
        product = it.get("product") or product_label(it)
        desc = one_line(it.get("description") or "")
        best_conf = it.get("confidence") or "unknown"
        if len(group) == 1:
            prog = it.get("program") or {}
            wild = " [WILDCARD]" if it.get("wildcard") or (
                (it.get("matched_asset") or {}).get("wildcard")
            ) else ""
            tag = privilege_tag_from_record(it)
            lines.append(
                f"{i}. {md_link(cve_id, nvd)} {tag} → "
                f"{md_link(prog.get('name') or '(unnamed program)', prog.get('url'))} "
                f"({prog.get('platform') or 'unknown platform'}){wild} [{best_conf}]"
            )
        else:
            tag = privilege_tag_from_record(it)
            lines.append(
                f"{i}. {md_link(cve_id, nvd)} {tag} → {len(group)} programs "
                f"({product}, CVSS {cvss_text(it)}) [{best_conf}]"
            )
        head = f"   {product}, CVSS {cvss_text(it)}."
        if desc:
            head += f" {desc}"
        lines.append(head)
        poc = it.get("poc")
        if not poc and it.get("pocs"):
            poc = best_poc(it.get("pocs"))
        lines.append(f"   {poc_bit(poc, cve_id=cve_id, product=product)}")
        if len(group) == 1:
            asset = it.get("matched_asset") or {}
            extras = []
            if asset.get("identifier"):
                typ = asset.get("type") or "asset"
                ident = str(asset["identifier"]).replace("`", "'")
                flag = " [WILDCARD]" if asset.get("wildcard") else ""
                extras.append(f"Matched asset ({typ}): `{ident}`{flag}")
            if it.get("reason"):
                extras.append(f"Reason: {it['reason']}")
            if extras:
                lines.append("   " + "  ·  ".join(extras))
        else:
            for pairing in group:
                lines.append("   " + pairing_program_line(pairing))
        lines.append("")

    groups = group_matches(items)
    exact_groups = [g for g in groups if group_is_exact(g)]
    possible_groups = [g for g in groups if not group_is_exact(g)]

    lines.append("### Confirmed exact-product matches")
    lines.append(
        "The affected product/vendor is a named in-scope asset or the vendor's "
        "own program — the trustworthy headline matches."
    )
    lines.append("")
    if exact_groups:
        for i, group in enumerate(exact_groups, 1):
            render_group(i, group)
    else:
        lines.append("None in this window.")
        lines.append("")

    if possible_groups:
        lines.append("### Possible — program runs the parent CMS (verify component is present)")
        lines.append(
            "Weaker matches: the program runs the parent platform "
            "(WordPress/Joomla/…), but the specific vulnerable plugin/component "
            "is NOT confirmed installed. Confirm the component is actually in use "
            "and in scope before testing, and only test where you are authorized."
        )
        lines.append("")
        for i, group in enumerate(possible_groups, 1):
            render_group(i, group)
    return "\n".join(lines)


def unmatched_items(
    feed: dict[str, Any],
    match: dict[str, Any],
    limit: int,
) -> list[dict[str, Any]]:
    matched_ids = {
        (it.get("cve_id") or "").upper()
        for it in (match.get("items") or [])
        if it.get("cve_id")
    }
    out: list[dict[str, Any]] = []
    for item in feed.get("items") or []:
        cve_id = (item.get("cve_id") or "").upper()
        if not cve_id or cve_id in matched_ids:
            continue
        out.append(item)
        if limit and len(out) >= limit:
            break
    return out


def render_section_c(
    feed: dict[str, Any],
    unmatched: list[dict[str, Any]],
    days: int,
) -> str:
    lines: list[str] = []
    lines.append("## C. Other notable recent CVEs with public PoCs (unmatched)")
    nvd_total = feed.get("nvd_published_in_window")
    poc_total = feed.get("matched_with_public_poc")
    bits = [f"Same {days}-day CVE window as section B."]
    if nvd_total is not None and poc_total is not None:
        bits.append(
            f"NVD published {nvd_total:,} CVE(s); {poc_total:,} had a public GitHub PoC."
        )
    bits.append(
        "These did not match a paid program's public scope in this pass; "
        "listed for awareness (feed rank order)."
    )
    lines.append(" ".join(bits))
    lines.append("")
    if not unmatched:
        lines.append("No unmatched CVEs with a public PoC in this window.")
        lines.append("")
        return "\n".join(lines)

    for i, item in enumerate(unmatched, 1):
        cve_id = item.get("cve_id") or "CVE-unknown"
        nvd = item.get("nvd_url")
        tag = privilege_tag_from_record(item)
        lines.append(
            f"{i}. {md_link(cve_id, nvd)} — CVSS {cvss_text(item)} — {product_label(item)} {tag}"
        )
        desc = item.get("description_one_line") or one_line(item.get("description") or "")
        pub = parse_dt(item.get("published"))
        pub_bit = f"Published {fmt_et(pub)}. " if pub else ""
        if desc:
            lines.append(f"   {pub_bit}{desc}")
        elif pub_bit:
            lines.append(f"   {pub_bit.strip()}")
        poc = best_poc(item.get("pocs") or [])
        extras = [poc_bit(poc, cve_id=item.get("cve_id"), product=product_label(item))]
        if item.get("bounty_relevant"):
            tags = item.get("bounty_tags") or []
            extras.append("Web-app relevant: " + (", ".join(tags) if tags else "yes"))
        lines.append("   " + "  ·  ".join(extras))
        lines.append("")
    return "\n".join(lines)


def render_markdown(
    *,
    generated: datetime,
    hours: float,
    days: int,
    monday_auto: bool,
    watch: dict[str, Any],
    match: dict[str, Any],
    feed: dict[str, Any],
    unmatched: list[dict[str, Any]],
) -> str:
    parts: list[str] = []
    parts.append("# Daily bug bounty digest")
    parts.append(
        f"Generated {fmt_et(generated, with_weekday=True)}  ·  "
        f"programs last {hours:g}h  ·  CVEs last {days} day(s)"
    )
    note = (match.get("privilege_note") or feed.get("privilege_note"))
    if note:
        parts.append(note)
    parts.append("")
    parts.append(render_section_a(watch, hours, monday_auto).rstrip())
    parts.append("")
    parts.append(render_section_b(match, days).rstrip())
    parts.append("")
    parts.append(render_section_c(feed, unmatched, days).rstrip())
    parts.append("")
    parts.append("---")
    parts.append(CAVEATS)
    parts.append("")
    return "\n".join(parts)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "One daily digest: new/changed bounty programs, CVE→program "
            "matches with PoC links, and unmatched CVEs with public PoCs."
        )
    )
    p.add_argument(
        "--hours",
        type=float,
        default=None,
        help=(
            "Lookback window in hours for section A (new programs and scope "
            f"changes). Default: {DEFAULT_HOURS_WEEKDAY}, or "
            f"{DEFAULT_HOURS_MONDAY} automatically on Mondays in America/New_York."
        ),
    )
    p.add_argument(
        "--days",
        type=int,
        default=DEFAULT_CVE_DAYS,
        help=(
            "Lookback window in days for sections B and C "
            f"(default: {DEFAULT_CVE_DAYS})."
        ),
    )
    p.add_argument("--json", action="store_true", help="Print JSON instead of markdown.")
    p.add_argument(
        "--no-pull",
        action="store_true",
        help="Skip git pull / feed refresh and use local clones and caches as-is.",
    )
    p.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        help=(
            "Pipeline data directory for clones and caches "
            "(default: $BOUNTY_PIPELINE_DIR, or this script's directory)."
        ),
    )
    p.add_argument(
        "--repo",
        type=Path,
        default=None,
        help=(
            "Local bounty-targets-data clone "
            "(default: <base-dir>/bounty-targets-data)."
        ),
    )
    p.add_argument(
        "--state-dir",
        type=Path,
        default=None,
        help="Where to write intermediate JSON caches (default: <base-dir>/state).",
    )
    p.add_argument(
        "--platform",
        default="all",
        help="hackerone, bugcrowd, intigriti, yeswehack, or all "
        "(default: all; comma-separated ok). Passed through to the matcher.",
    )
    add_priv_level_argument(p)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    generated = now_et()
    monday_auto = args.hours is None and generated.weekday() == 0
    hours = weekday_hours(generated) if args.hours is None else args.hours
    if hours <= 0:
        die("--hours must be positive")
    if args.days < 1:
        die("--days must be >= 1")
    if args.days > 120:
        die("NVD date-range queries are capped at 120 days; use a smaller --days")

    pull = not args.no_pull
    base = resolve_base(args.base_dir)
    if args.base_dir:
        os.environ["BOUNTY_PIPELINE_DIR"] = str(base)
    repo = (args.repo or (base / "bounty-targets-data")).expanduser().resolve()
    state_dir = (args.state_dir or (base / "state")).expanduser().resolve()
    state_dir.mkdir(parents=True, exist_ok=True)

    # Clone the public program-scope repo if needed; pull when not --no-pull.
    ensure_bounty_targets(repo, pull=pull)

    # --- Section A: program / scope watch ---------------------------------
    watch_cmd = [
        sys.executable,
        str(WATCH_SCRIPT),
        "--repo",
        str(repo),
        "--hours",
        str(hours),
        "--json",
    ]
    # Already pulled above when requested; do not pull again inside watch.py.
    watch = run_json(watch_cmd, timeout=300, allow_empty_watch=True)

    # --- CVE feed (shared by B and C) -------------------------------------
    feed_path = state_dir / f"cve-poc-feed-{args.days}d.json"
    dated_path = state_dir / f"cve-poc-feed-{generated.strftime('%Y-%m-%d')}.json"
    feed: dict[str, Any] | None = None
    if not pull and feed_path.is_file():
        try:
            cached = json.loads(feed_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Cached CVE feed unreadable ({exc}); refreshing.", file=sys.stderr)
            cached = None
        if isinstance(cached, dict) and cached.get("items") is not None:
            cached_days = cached.get("window_days")
            if cached_days in (None, args.days):
                feed = cached
                print(f"Reusing cached CVE feed {feed_path} (--no-pull)", file=sys.stderr)
            else:
                print(
                    f"Cached feed is {cached_days}d, need {args.days}d; refreshing.",
                    file=sys.stderr,
                )

    if feed is None:
        feed_cmd = [
            sys.executable,
            str(FEED_SCRIPT),
            "--days",
            str(args.days),
            "--json",
            "--limit",
            "0",
            "--state-dir",
            str(state_dir),
            "--priv-level",
            args.priv_level,
        ]
        if pull:
            feed_cmd.append("--pull")
        # NVD unauthenticated pagination can be slow; allow a long window.
        feed = run_json(feed_cmd, timeout=1200)
        payload_text = json.dumps(feed, indent=2) + "\n"
        feed_path.write_text(payload_text, encoding="utf-8")
        dated_path.write_text(payload_text, encoding="utf-8")
        print(f"Wrote CVE feed JSON to {feed_path}", file=sys.stderr)

    # Classify + apply --priv-level. Idempotent if the feed was already filtered
    # at this level; also covers a --no-pull cache written before the filter existed.
    feed = filter_feed_payload(feed, args.priv_level)
    match_feed_path = state_dir / f"cve-poc-feed-{args.days}d.priv-{args.priv_level}.json"
    try:
        match_feed_path.write_text(json.dumps(feed, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        die(f"Could not write filtered feed to {match_feed_path}: {exc}")

    # --- Section B: CVE → program matches ---------------------------------
    match_cmd = [
        sys.executable,
        str(MATCH_SCRIPT),
        "--days",
        str(args.days),
        "--json",
        "--feed-json",
        str(match_feed_path),
        "--repo",
        str(repo),
        "--priv-level",
        args.priv_level,
        "--platform",
        args.platform,
    ]
    match = run_json(match_cmd, timeout=300)
    match_path = state_dir / f"cve-program-match-{args.days}d.priv-{args.priv_level}.json"
    try:
        match_path.write_text(json.dumps(match, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote program-match JSON to {match_path}", file=sys.stderr)
    except OSError as exc:
        print(f"Warning: could not cache match JSON at {match_path}: {exc}", file=sys.stderr)

    unmatched = unmatched_items(feed, match, DEFAULT_UNMATCHED_LIMIT)

    if args.json:
        json.dump(
            {
                "generated_at": generated.isoformat(),
                "timezone": "America/New_York",
                "hours": hours,
                "monday_auto_window": monday_auto,
                "days": args.days,
                "pulled": pull,
                "priv_level": args.priv_level,
                "privilege_counts": feed.get("privilege_counts"),
                "privilege_dropped": feed.get("privilege_dropped"),
                "privilege_kept": feed.get("privilege_kept"),
                "privilege_note": feed.get("privilege_note") or filter_note(
                    feed.get("privilege_counts") or {}, args.priv_level
                )
                if feed.get("privilege_counts") is not None
                else None,
                "section_a": watch,
                "section_b": match,
                "section_c": {
                    "unmatched_shown": unmatched,
                    "unmatched_limit": DEFAULT_UNMATCHED_LIMIT,
                    "feed_meta": {k: v for k, v in feed.items() if k != "items"},
                },
                "caveats": CAVEATS,
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        sys.stdout.write(
            render_markdown(
                generated=generated,
                hours=hours,
                days=args.days,
                monday_auto=monday_auto,
                watch=watch,
                match=match,
                feed=feed,
                unmatched=unmatched,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
