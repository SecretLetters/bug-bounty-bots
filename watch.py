#!/usr/bin/env python3
"""Watch public bug bounty program and scope changes.

Diffs snapshots from a local clone of https://github.com/arkadiyt/bounty-targets-data
(HackerOne, Bugcrowd, Intigriti, YesWeHack) across a time window.

Default filters:
  * drop VDPs / programs that do not offer bounties
  * drop programs whose known max payout is under $100 (see --min-max-usd)
  * skip redacted or cosmetic target-string changes
  * treat programs that existed before the window as reappearances, not launches

Examples:
  python3 watch.py --hours 24
  python3 watch.py --days 7
  python3 watch.py --since '2026-11-18T09:36:00-05:00'
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
from paths import bounty_targets_repo  # noqa: E402


DEFAULT_REPO = bounty_targets_repo()
DATA_FILES = {
    "HackerOne": "data/hackerone_data.json",
    "Bugcrowd": "data/bugcrowd_data.json",
    "Intigriti": "data/intigriti_data.json",
    "YesWeHack": "data/yeswehack_data.json",
}
# Used only to apply the --min-max-usd floor to non-USD payouts.
DEFAULT_FX = {"USD": 1.0, "EUR": 1.15, "GBP": 1.30}
REDACTED_RE = re.compile(r"^[\s█■▉▇▓*xX]+$")
SCHEME_RE = re.compile(r"^https?://", re.I)


def die(msg: str, code: int = 1) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def run_git(repo: Path, *args: str) -> str:
    try:
        return subprocess.check_output(
            ["git", *args], cwd=repo, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except subprocess.CalledProcessError as exc:
        die(f"git {' '.join(args)} failed in {repo}: {exc}")
        return ""


def parse_git_datetime(stamp: str) -> datetime:
    # "2026-11-25 14:36:23 +0000"
    return datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S %z")


def parse_user_datetime(value: str) -> datetime:
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        die(f"Could not parse --since timestamp: {value!r} (use ISO-8601)")
        raise
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def load_json_at(repo: Path, commit: str, relpath: str) -> Any:
    """Load a JSON path from a commit. Missing paths (early history) yield []."""
    try:
        raw = subprocess.check_output(
            ["git", "show", f"{commit}:{relpath}"], cwd=repo, stderr=subprocess.DEVNULL
        )
    except subprocess.CalledProcessError:
        return []
    if not raw or not raw.strip():
        return []
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Program / target accessors
# ---------------------------------------------------------------------------

def program_id(platform: str, prog: dict) -> str:
    if platform == "HackerOne":
        return prog.get("handle") or prog.get("url") or prog.get("name") or ""
    if platform == "Bugcrowd":
        return prog.get("url") or prog.get("name") or ""
    if platform == "Intigriti":
        return prog.get("handle") or prog.get("id") or prog.get("url") or ""
    return prog.get("id") or prog.get("name") or ""


def program_name(prog: dict) -> str:
    return (prog.get("name") or program_id("", prog) or "").strip()


def program_url(platform: str, prog: dict) -> str:
    if platform == "YesWeHack":
        pid = prog.get("id") or ""
        return f"https://yeswehack.com/programs/{pid}" if pid else ""
    return prog.get("url") or ""


def payout_info(platform: str, prog: dict) -> dict:
    """Return min/max payout as numeric values plus a display string."""
    info = {
        "offers_bounties": False,
        "min": None,
        "max": None,
        "currency": None,
        "min_display": None,
        "max_display": None,
    }
    if platform == "HackerOne":
        offers = bool(prog.get("offers_bounties"))
        info["offers_bounties"] = offers
        # Amounts are not present in bounty-targets-data for HackerOne.
        return info
    if platform == "Bugcrowd":
        mx = prog.get("max_payout")
        if mx is None:
            return info
        try:
            mx_n = float(mx)
        except (TypeError, ValueError):
            return info
        info["max"] = mx_n
        info["currency"] = "USD"
        info["max_display"] = format_money(mx_n, "USD")
        info["offers_bounties"] = mx_n > 0
        return info
    if platform == "Intigriti":
        mn = prog.get("min_bounty") or {}
        mx = prog.get("max_bounty") or {}
        currency = mx.get("currency") or mn.get("currency") or "EUR"
        min_v = mn.get("value")
        max_v = mx.get("value")
        if min_v is not None:
            info["min"] = float(min_v)
            info["min_display"] = format_money(info["min"], currency)
        if max_v is not None:
            info["max"] = float(max_v)
            info["max_display"] = format_money(info["max"], currency)
        info["currency"] = currency
        info["offers_bounties"] = (info["max"] or 0) > 0
        return info
    # YesWeHack: amounts are present but the dump has no currency field.
    min_v = prog.get("min_bounty")
    max_v = prog.get("max_bounty")
    currency = None
    if min_v is not None:
        info["min"] = float(min_v)
        info["min_display"] = format_money(info["min"], currency)
    if max_v is not None:
        info["max"] = float(max_v)
        info["max_display"] = format_money(info["max"], currency)
    info["currency"] = currency
    info["offers_bounties"] = (info["max"] or 0) > 0
    return info


def format_money(value: float | None, currency: str | None) -> str:
    if value is None:
        return "unknown"
    cur = (currency or "").upper()
    symbol = {"USD": "$", "EUR": "€", "GBP": "£"}.get(cur, (cur + " ") if cur else "")
    if float(value).is_integer():
        return f"{symbol}{int(value):,}"
    return f"{symbol}{value:,.2f}"


def payout_line(info: dict) -> str:
    mn, mx = info.get("min_display"), info.get("max_display")
    suffix = ""
    if (mn or mx) and not info.get("currency"):
        suffix = " (currency not in dataset)"
    if mn and mx:
        return f"min {mn} / max {mx}{suffix}"
    if mx and not mn:
        return f"min unknown / max {mx}{suffix}"
    if mn and not mx:
        return f"min {mn} / max unknown{suffix}"
    if info.get("offers_bounties"):
        return "min unknown / max unknown (offers bounties; amounts not in dataset)"
    return "no bounty / VDP"


def to_usd(amount: float | None, currency: str | None, fx: dict[str, float]) -> float | None:
    if amount is None:
        return None
    if not currency:
        # YesWeHack and similar: no currency in the dump. Apply the USD floor to the raw
        # number so a max of 50 is dropped and a max of 2000 is kept.
        return amount
    cur = currency.upper()
    rate = fx.get(cur)
    if rate is None:
        return amount
    return amount * rate


def passes_payout_filter(
    info: dict,
    include_vdp: bool,
    min_max_usd: float | None,
    fx: dict[str, float],
) -> bool:
    if not info.get("offers_bounties"):
        return bool(include_vdp)
    if min_max_usd is None:
        return True
    max_usd = to_usd(info.get("max"), info.get("currency"), fx)
    if max_usd is None:
        # HackerOne (and any other program with no published max in the dump):
        # keep it when it offers bounties, because we cannot show it is under the floor.
        return True
    return max_usd >= min_max_usd


def in_scope_targets(platform: str, prog: dict) -> list[dict]:
    raw = ((prog.get("targets") or {}).get("in_scope") or [])
    out = []
    for t in raw:
        if platform == "HackerOne":
            ident = t.get("asset_identifier") or ""
            typ = t.get("asset_type") or ""
        elif platform == "Bugcrowd":
            ident = t.get("target") or t.get("uri") or t.get("name") or ""
            typ = t.get("type") or ""
        elif platform == "Intigriti":
            ident = t.get("endpoint") or ""
            typ = t.get("type") or ""
        else:
            ident = t.get("target") or ""
            typ = t.get("type") or ""
        if not ident or not str(ident).strip():
            continue
        out.append({"id": str(ident), "type": str(typ), "raw": t})
    return out


def normalize_target(identifier: str) -> str:
    s = identifier.strip().lower()
    s = s.replace("\t", "").strip()
    s = SCHEME_RE.sub("", s)
    s = s.rstrip("/")
    return s


def is_redacted(identifier: str) -> bool:
    compact = re.sub(r"\s+", "", identifier)
    if not compact:
        return False
    return bool(REDACTED_RE.match(compact)) or (compact.count("█") / max(len(compact), 1) > 0.7)


def is_wildcard(identifier: str, typ: str) -> bool:
    t = (typ or "").lower()
    if t in {"wildcard", "wild_card"}:
        return True
    s = identifier.strip()
    if not s:
        return False
    if s.startswith("*.") or s.startswith("*") or "*. " in s:
        return True
    if re.search(r"(^|[./])\*\.", s):
        return True
    # e.g. https://*.example.com or *nubank.world or www.example.(com|net)
    if re.search(r"\*\w", s) or "(" in s and "|" in s:
        return True
    return False


def target_key(identifier: str, typ: str) -> tuple[str, str]:
    return (normalize_target(identifier), (typ or "").lower())


# ---------------------------------------------------------------------------
# Git snapshot selection
# ---------------------------------------------------------------------------

@dataclass
class Commit:
    sha: str
    when: datetime


def list_commits(repo: Path) -> list[Commit]:
    log = run_git(repo, "log", "--format=%h %ci")
    commits: list[Commit] = []
    for line in log.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        sha, date, time, tz = parts[0], parts[1], parts[2], parts[3]
        commits.append(Commit(sha, parse_git_datetime(f"{date} {time} {tz}")))
    commits.sort(key=lambda c: c.when)
    return commits


def closest_commit(commits: list[Commit], when: datetime) -> Commit | None:
    """Return the commit closest in time to `when` (prefers the earlier one on a tie)."""
    if not commits:
        return None
    return min(commits, key=lambda c: (abs((c.when - when).total_seconds()), c.when))


def load_platform_index(repo: Path, commit: str, platform: str) -> dict[str, dict]:
    path = DATA_FILES[platform]
    data = load_json_at(repo, commit, path)
    if not isinstance(data, list):
        return {}
    index = {}
    for prog in data:
        pid = program_id(platform, prog)
        if pid:
            index[pid] = prog
    return index


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

@dataclass
class TargetHit:
    identifier: str
    typ: str
    wildcard: bool


@dataclass
class ProgramHit:
    platform: str
    pid: str
    name: str
    url: str
    payout: dict
    targets: list[TargetHit] = field(default_factory=list)
    first_seen: datetime | None = None
    returning: bool = False


def first_seen_in_commits(
    repo: Path,
    platform: str,
    pid: str,
    commits: list[Commit],
    start: Commit,
    end: Commit,
) -> datetime | None:
    """Earliest commit in (start, end] whose platform file adds or still contains pid."""
    relpath = DATA_FILES[platform]
    # git log -S is much faster than reading every snapshot. Filter to after baseline
    # (the first shallow commit will otherwise look like an "add" for everything in it).
    # Bound the pickaxe to the window. This function only returns a timestamp
    # in (start, end], and an unbounded -S over the full repo history is too
    # slow on a complete clone (~hourly commits, multi-MB JSON files).
    try:
        log = subprocess.check_output(
            [
                "git",
                "log",
                "--reverse",
                "--format=%h %ci",
                "-S",
                pid,
                "--since",
                start.when.strftime("%Y-%m-%d %H:%M:%S %z"),
                "--until",
                end.when.strftime("%Y-%m-%d %H:%M:%S %z"),
                "--",
                relpath,
            ],
            cwd=repo,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except subprocess.CalledProcessError:
        log = ""
    for line in log.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        when = parse_git_datetime(f"{parts[1]} {parts[2]} {parts[3]}")
        if start.when < when <= end.when:
            # Confirm the program is actually present at that commit (the string may
            # appear for other reasons, or the commit may be a removal).
            index = load_platform_index(repo, parts[0], platform)
            if pid in index:
                return when
    # Fallback: coarse forward scan in case -S missed a handle-only change.
    window = [c for c in commits if start.when < c.when <= end.when]
    stride = 8
    last_miss = start
    for c in window[::stride] + [window[-1]]:
        index = load_platform_index(repo, c.sha, platform)
        if pid in index:
            # Refine inside (last_miss, c]
            refine = [x for x in window if last_miss.when < x.when <= c.when]
            for x in refine:
                if pid in load_platform_index(repo, x.sha, platform):
                    return x.when
            return c.when
        last_miss = c
    return end.when


def diff_window(
    repo: Path,
    baseline: Commit,
    head: Commit,
    commits: list[Commit],
    include_vdp: bool,
    min_max_usd: float | None,
    fx: dict[str, float],
    check_history: bool,
    locate_first_seen: bool,
) -> dict:
    earlier = [c for c in commits if c.when < baseline.when]
    history_indexes: dict[str, set[str]] = {p: set() for p in DATA_FILES}
    if check_history and earlier:
        # Union of program ids from the earliest snapshot and the last one before baseline.
        samples = [earlier[0]]
        if earlier[-1].sha != earlier[0].sha:
            samples.append(earlier[-1])
        # Also sample a midpoint if the pre-window history is long.
        if len(earlier) > 4:
            samples.append(earlier[len(earlier) // 2])
        for sample in samples:
            for platform in DATA_FILES:
                history_indexes[platform] |= set(
                    load_platform_index(repo, sample.sha, platform)
                )

    result = {
        "new_programs": [],
        "returning_programs": [],
        "scope_additions": [],
        "bounty_changes": [],
        "skipped_low_payout_or_vdp": {"new": 0, "scope_programs": 0},
        "raw_counts": {},
    }

    for platform in DATA_FILES:
        old = load_platform_index(repo, baseline.sha, platform)
        new = load_platform_index(repo, head.sha, platform)
        added_ids = [pid for pid in new if pid not in old]
        removed_ids = [pid for pid in old if pid not in new]
        result["raw_counts"][platform] = {
            "baseline_programs": len(old),
            "head_programs": len(new),
            "appeared": len(added_ids),
            "disappeared": len(removed_ids),
        }

        for pid in added_ids:
            prog = new[pid]
            info = payout_info(platform, prog)
            if not passes_payout_filter(info, include_vdp, min_max_usd, fx):
                result["skipped_low_payout_or_vdp"]["new"] += 1
                continue
            tgs = [
                TargetHit(t["id"], t["type"], is_wildcard(t["id"], t["type"]))
                for t in in_scope_targets(platform, prog)
                if not is_redacted(t["id"])
            ]
            hit = ProgramHit(
                platform=platform,
                pid=pid,
                name=program_name(prog),
                url=program_url(platform, prog),
                payout=info,
                targets=tgs,
                returning=pid in history_indexes.get(platform, set()),
            )
            if locate_first_seen:
                hit.first_seen = first_seen_in_commits(
                    repo, platform, pid, commits, baseline, head
                )
            if hit.returning:
                result["returning_programs"].append(hit)
            else:
                result["new_programs"].append(hit)

        for pid, prog in new.items():
            if pid not in old:
                continue
            info = payout_info(platform, prog)
            if not passes_payout_filter(info, include_vdp, min_max_usd, fx):
                result["skipped_low_payout_or_vdp"]["scope_programs"] += 1
                continue
            old_keys = {
                target_key(t["id"], t["type"])
                for t in in_scope_targets(platform, old[pid])
                if not is_redacted(t["id"])
            }
            added_t: list[TargetHit] = []
            for t in in_scope_targets(platform, prog):
                if is_redacted(t["id"]):
                    continue
                if target_key(t["id"], t["type"]) in old_keys:
                    continue
                # Also treat identifier-only match (type flip / scheme already normalized) as not new.
                if any(normalize_target(t["id"]) == k[0] for k in old_keys):
                    continue
                added_t.append(
                    TargetHit(t["id"], t["type"], is_wildcard(t["id"], t["type"]))
                )
            if added_t:
                result["scope_additions"].append(
                    ProgramHit(
                        platform=platform,
                        pid=pid,
                        name=program_name(prog),
                        url=program_url(platform, prog),
                        payout=info,
                        targets=added_t,
                    )
                )

            old_info = payout_info(platform, old[pid])
            if (old_info.get("min"), old_info.get("max"), old_info.get("offers_bounties")) != (
                info.get("min"),
                info.get("max"),
                info.get("offers_bounties"),
            ):
                # Keep a change even if the new max is below the floor, so cuts are visible,
                # but still drop pure VDPs unless --include-vdp.
                if info.get("offers_bounties") or old_info.get("offers_bounties") or include_vdp:
                    result["bounty_changes"].append(
                        {
                            "platform": platform,
                            "name": program_name(prog),
                            "url": program_url(platform, prog),
                            "old": old_info,
                            "new": info,
                        }
                    )

    def sort_key(hit: ProgramHit):
        wild = sum(1 for t in hit.targets if t.wildcard)
        mx = hit.payout.get("max") or 0
        return (wild, mx, len(hit.targets), hit.name.lower())

    result["new_programs"].sort(key=sort_key, reverse=True)
    result["returning_programs"].sort(key=sort_key, reverse=True)
    result["scope_additions"].sort(key=sort_key, reverse=True)
    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def format_when(dt: datetime | None) -> str:
    if dt is None:
        return "unknown"
    # Display in America/New_York as well as UTC.
    try:
        from zoneinfo import ZoneInfo

        et = dt.astimezone(ZoneInfo("America/New_York"))
        return f"{et.strftime('%Y-%m-%d %H:%M %Z')} ({dt.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')})"
    except Exception:
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def render_targets(targets: list[TargetHit], limit: int | None = None) -> list[str]:
    lines = []
    shown = targets if limit is None else targets[:limit]
    for t in shown:
        flag = " [WILDCARD]" if t.wildcard else ""
        typ = f" ({t.typ})" if t.typ else ""
        lines.append(f"    + {t.identifier.strip()}{typ}{flag}")
    if limit is not None and len(targets) > limit:
        lines.append(f"    ... +{len(targets) - limit} more")
    return lines


def render_text(
    result: dict,
    baseline: Commit,
    head: Commit,
    min_max_usd: float | None,
    include_vdp: bool,
) -> str:
    lines: list[str] = []
    lines.append("Bug bounty watch")
    lines.append(
        f"Window: {format_when(baseline.when)}  ->  {format_when(head.when)}"
    )
    lines.append(f"Commits: {baseline.sha}  ->  {head.sha}")
    filt = []
    if not include_vdp:
        filt.append("VDPs / no-bounty excluded")
    if min_max_usd is not None:
        filt.append(f"max payout < ${min_max_usd:g} excluded (unknown max kept if offers bounties)")
    lines.append("Filters: " + (", ".join(filt) if filt else "none"))
    lines.append("")

    def section(title: str, hits: list[ProgramHit], empty: str) -> None:
        lines.append("=" * 72)
        lines.append(f"{title} ({len(hits)})")
        lines.append("=" * 72)
        if not hits:
            lines.append(empty)
            lines.append("")
            return
        for hit in hits:
            seen = f"  first seen in dump: {format_when(hit.first_seen)}" if hit.first_seen else ""
            wild = sum(1 for t in hit.targets if t.wildcard)
            lines.append(f"{hit.name}  [{hit.platform}]")
            lines.append(f"  {payout_line(hit.payout)}")
            if hit.url:
                lines.append(f"  {hit.url}")
            if seen:
                lines.append(seen)
            if hit.targets:
                label = f"  in-scope listed ({len(hit.targets)}, {wild} wildcard):" if title.startswith("New") or title.startswith("Returning") else f"  added assets ({len(hit.targets)}, {wild} wildcard):"
                lines.append(label)
                lines.extend(render_targets(hit.targets, limit=20))
            lines.append("")

    section(
        "New bounty programs (not seen before this window in the local clone)",
        result["new_programs"],
        "  (none after filters)",
    )
    section(
        "Reappeared / returning programs (present before the window, missing at baseline, back now)",
        result["returning_programs"],
        "  (none after filters)",
    )
    section(
        "Scope additions on existing bounty programs",
        result["scope_additions"],
        "  (none after filters)",
    )

    lines.append("=" * 72)
    lines.append(f"Bounty amount changes ({len(result['bounty_changes'])})")
    lines.append("=" * 72)
    if not result["bounty_changes"]:
        lines.append("  (none detected in dataset payout fields)")
        lines.append("")
    else:
        for ch in result["bounty_changes"]:
            old, new = ch["old"], ch["new"]
            direction = ""
            if old.get("max") is not None and new.get("max") is not None:
                if new["max"] > old["max"]:
                    direction = "  INCREASE"
                elif new["max"] < old["max"]:
                    direction = "  DECREASE"
            lines.append(f"{ch['name']}  [{ch['platform']}]{direction}")
            lines.append(f"  {payout_line(old)}  ->  {payout_line(new)}")
            if ch.get("url"):
                lines.append(f"  {ch['url']}")
            lines.append("")

    lines.append("=" * 72)
    lines.append("Counts")
    lines.append("=" * 72)
    new_n = len(result["new_programs"])
    ret_n = len(result["returning_programs"])
    scope_n = len(result["scope_additions"])
    scope_assets = sum(len(h.targets) for h in result["scope_additions"])
    scope_wild = sum(sum(1 for t in h.targets if t.wildcard) for h in result["scope_additions"])
    lines.append(f"  New programs (after filters, excluding reappearances): {new_n}")
    lines.append(f"  Returning programs (after filters): {ret_n}")
    lines.append(f"  Programs with real scope additions: {scope_n}")
    lines.append(f"  New in-scope assets (after noise filter): {scope_assets}  ({scope_wild} wildcard)")
    lines.append(f"  Bounty amount field changes: {len(result['bounty_changes'])}")
    skipped = result["skipped_low_payout_or_vdp"]
    lines.append(
        f"  Skipped as VDP / below max-payout floor: {skipped['new']} programs that appeared in the window, "
        f"and {skipped['scope_programs']} programs already in the directory (those were not checked for scope additions)"
    )
    for platform, c in result["raw_counts"].items():
        lines.append(
            f"  {platform} raw directory: {c['baseline_programs']} -> {c['head_programs']} "
            f"(appeared {c['appeared']}, disappeared {c['disappeared']})"
        )
    lines.append("")
    return "\n".join(lines)


def hit_to_json(hit: ProgramHit) -> dict:
    return {
        "name": hit.name,
        "platform": hit.platform,
        "id": hit.pid,
        "url": hit.url,
        "min_payout": hit.payout.get("min_display"),
        "max_payout": hit.payout.get("max_display"),
        "min_value": hit.payout.get("min"),
        "max_value": hit.payout.get("max"),
        "currency": hit.payout.get("currency"),
        "offers_bounties": hit.payout.get("offers_bounties"),
        "first_seen": hit.first_seen.isoformat() if hit.first_seen else None,
        "returning": hit.returning,
        "targets": [
            {"id": t.identifier, "type": t.typ, "wildcard": t.wildcard}
            for t in hit.targets
        ],
        "wildcard_count": sum(1 for t in hit.targets if t.wildcard),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Diff public bug bounty programs and in-scope targets over a time window.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument("--hours", type=float, help="Look back this many hours from HEAD.")
    g.add_argument("--days", type=float, help="Look back this many days from HEAD.")
    p.add_argument(
        "--since",
        help="ISO-8601 start time (overrides --hours/--days). Example: 2026-11-24T09:36:00-05:00",
    )
    p.add_argument(
        "--repo",
        type=Path,
        default=None,
        help=(
            "Path to a bounty-targets-data clone "
            "(default: $BOUNTY_PIPELINE_DIR/bounty-targets-data, "
            "or <script-dir>/bounty-targets-data)."
        ),
    )
    p.add_argument(
        "--pull",
        action="store_true",
        help="git pull --ff-only in the clone before diffing.",
    )
    p.add_argument(
        "--min-max-usd",
        type=float,
        default=100,
        metavar="USD",
        help=(
            "Drop programs whose known max payout converts to less than this many USD "
            "(default: 100). HackerOne programs have no amounts in the dataset; they are "
            "kept if they offer bounties. Use --no-min-max to disable."
        ),
    )
    p.add_argument(
        "--no-min-max",
        action="store_true",
        help="Disable the default $100 max-payout floor.",
    )
    p.add_argument(
        "--include-vdp",
        action="store_true",
        help="Also include programs that do not offer bounties (VDPs).",
    )
    p.add_argument(
        "--no-history-check",
        action="store_true",
        help="Do not check pre-window history; treat every appearance vs baseline as new.",
    )
    p.add_argument(
        "--no-first-seen",
        action="store_true",
        help="Skip binary-searching first-seen timestamps (faster).",
    )
    p.add_argument(
        "--eur-usd",
        type=float,
        default=DEFAULT_FX["EUR"],
        help=f"EUR to USD rate for the max-payout floor (default: {DEFAULT_FX['EUR']}).",
    )
    p.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo = (args.repo or DEFAULT_REPO).expanduser().resolve()
    if not (repo / ".git").exists():
        die(
            f"No git repo at {repo}. Clone https://github.com/arkadiyt/bounty-targets-data "
            f"there first (a shallow clone with --shallow-since is fine)."
        )
    if args.pull:
        try:
            subprocess.check_call(["git", "pull", "--ff-only"], cwd=repo)
        except subprocess.CalledProcessError:
            die("git pull --ff-only failed")

    commits = list_commits(repo)
    if not commits:
        die("No commits found in repo")
    head = commits[-1]

    if args.since:
        start_time = parse_user_datetime(args.since)
    else:
        hours = args.hours if args.hours is not None else (args.days or 7) * 24
        start_time = head.when - timedelta(hours=hours)

    baseline = closest_commit(commits, start_time)
    if baseline is None:
        die(
            f"No commit at or before {start_time.isoformat()}. "
            f"Oldest commit in this clone is {commits[0].sha} {commits[0].when.isoformat()}."
        )
    if baseline.sha == head.sha:
        die("Baseline and HEAD are the same commit; widen the window.")

    min_max_usd = None if args.no_min_max else args.min_max_usd
    fx = dict(DEFAULT_FX)
    fx["EUR"] = args.eur_usd

    result = diff_window(
        repo=repo,
        baseline=baseline,
        head=head,
        commits=commits,
        include_vdp=args.include_vdp,
        min_max_usd=min_max_usd,
        fx=fx,
        check_history=not args.no_history_check,
        locate_first_seen=not args.no_first_seen,
    )

    if args.json:
        payload = {
            "window": {
                "baseline_commit": baseline.sha,
                "baseline_time": baseline.when.isoformat(),
                "head_commit": head.sha,
                "head_time": head.when.isoformat(),
            },
            "filters": {
                "include_vdp": args.include_vdp,
                "min_max_usd": min_max_usd,
                "eur_usd": args.eur_usd,
            },
            "new_programs": [hit_to_json(h) for h in result["new_programs"]],
            "returning_programs": [hit_to_json(h) for h in result["returning_programs"]],
            "scope_additions": [hit_to_json(h) for h in result["scope_additions"]],
            "bounty_changes": [
                {
                    "name": ch["name"],
                    "platform": ch["platform"],
                    "url": ch["url"],
                    "old": payout_line(ch["old"]),
                    "new": payout_line(ch["new"]),
                    "old_min": ch["old"].get("min"),
                    "old_max": ch["old"].get("max"),
                    "new_min": ch["new"].get("min"),
                    "new_max": ch["new"].get("max"),
                    "currency": ch["new"].get("currency") or ch["old"].get("currency"),
                }
                for ch in result["bounty_changes"]
            ],
            "counts": {
                "new_programs": len(result["new_programs"]),
                "returning_programs": len(result["returning_programs"]),
                "scope_programs": len(result["scope_additions"]),
                "scope_assets": sum(len(h.targets) for h in result["scope_additions"]),
                "scope_wildcards": sum(
                    sum(1 for t in h.targets if t.wildcard) for h in result["scope_additions"]
                ),
                "bounty_changes": len(result["bounty_changes"]),
                "skipped_low_payout_or_vdp": result["skipped_low_payout_or_vdp"],
                "raw": result["raw_counts"],
            },
        }
        print(json.dumps(payload, indent=2))
    else:
        sys.stdout.write(
            render_text(result, baseline, head, min_max_usd, args.include_vdp)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
