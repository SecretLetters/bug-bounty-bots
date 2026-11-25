#!/usr/bin/env python3
"""Privilege-level classification and filtering for the bug bounty CVE pipeline.

Primary signal: the CVSS Privileges Required metric (PR:N / PR:L / PR:H) from
an NVD vector or metric field. CVSS v2 Authentication (Au:N / Au:S / Au:M) is
mapped to the same scale. Text in the CVE description is a fallback only when
the vector is missing.

This module is metadata-only: it does not fetch, scan, or exploit anything.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Callable, Iterable, Literal


PRIV_UNAUTH = "unauth"
PRIV_LOW = "low"
PRIV_HIGH = "high"
PRIV_UNKNOWN = "unknown"

PRIVILEGE_VALUES = (PRIV_UNAUTH, PRIV_LOW, PRIV_HIGH, PRIV_UNKNOWN)
PrivLevel = Literal["unauth", "unauth-or-unknown", "all"]
PRIV_LEVEL_CHOICES = ("unauth", "unauth-or-unknown", "all")
DEFAULT_PRIV_LEVEL: PrivLevel = "unauth"

PR_TO_PRIV = {"N": PRIV_UNAUTH, "L": PRIV_LOW, "H": PRIV_HIGH}
PRIV_TO_PR = {PRIV_UNAUTH: "N", PRIV_LOW: "L", PRIV_HIGH: "H"}

# Microsoft / NVD metric field names, uppercased.
_FIELD_TO_PR = {
    "NONE": "N",
    "LOW": "L",
    "HIGH": "H",
    "SINGLE": "L",  # CVSS v2 authentication
    "MULTIPLE": "H",
}

# Strong unauth / pre-auth phrasing. "unauthenticated" is matched as a whole
# word so it is not swallowed by an "authenticated" pattern.
_UNAUTH_RE = re.compile(
    r"""
    \b(
        unauthenticated
        | pre-auth(?:entication)?s?
        | preauth
        | without(?:\s+any)?\s+authentication
        | (?:does\s+not|doesn't|do\s+not)\s+require(?:\s+any)?\s+authentication
        | requires?\s+no\s+authentication
        | no\s+authentication(?:\s+(?:required|needed))?
        | no\s+privileges?\s+required
        | unauthori[sz]ed\s+attacker
        | anonymously
        | as\s+an?\s+anonymous
    )
    \b
    """,
    re.IGNORECASE | re.VERBOSE,
)

_HIGH_RE = re.compile(
    r"""
    \b(
        requires?\s+(?:an?\s+)?(?:admin(?:istrator)?|root)\b
        | authenticated\s+(?:admin(?:istrator)?s?|admins?)
        | (?:admin(?:istrator)?|root)\s+privileges?
        | with\s+admin(?:istrator)?\s+(?:access|privileges?|rights?|permissions?)
        | high(?:ly)?[- ]privileg
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_LOW_RE = re.compile(
    r"""
    \b(
        authenticated\s+(?:attacker|user|users|actor|request|requests|session)
        | requires?\s+(?:an?\s+)?(?:valid\s+)?(?:authentication|authenticated)
        | logged[- ]in
        | low[- ]privileg
        | with\s+(?:valid\s+)?credentials
        | authori[sz]ed\s+attacker
        | an\s+authenticated
    )
    \b
    """,
    re.IGNORECASE | re.VERBOSE,
)


def parse_pr_from_vector(vector: str | None, cvss_version: str | None = None) -> str | None:
    """Return 'N', 'L', or 'H' from a CVSS vector, or None if not present.

    Matches `/PR:N` (and v3/v4 variants) but not CVSS v4 `/MPR:` (modified PR).
    CVSS v2 `Au:N/S/M` is mapped to N/L/H. CVSS v4 `AU:` (Automatable) is ignored.
    """
    if not vector:
        return None
    text = str(vector).strip()
    # Require a slash or start so MPR: is not treated as PR:.
    m = re.search(r"(?:^|/)PR:([NLH])(?:/|$)", text)
    if m:
        return m.group(1)
    is_v2 = (str(cvss_version or "").startswith("2") or text.upper().startswith("CVSS:2"))
    if is_v2:
        m = re.search(r"(?:^|/)Au:([NSM])(?:/|$)", text, re.IGNORECASE)
        if m:
            return {"N": "N", "S": "L", "M": "H"}[m.group(1).upper()]
    return None


def parse_pr_from_fields(
    privileges_required: str | None = None,
    authentication: str | None = None,
) -> str | None:
    """Map NVD metric field values (NONE/LOW/HIGH or v2 NONE/SINGLE/MULTIPLE)."""
    for raw in (privileges_required, authentication):
        if not raw:
            continue
        key = str(raw).strip().upper()
        if key in _FIELD_TO_PR:
            return _FIELD_TO_PR[key]
    return None


def classify_from_text(description: str | None) -> str:
    """Best-effort privilege from advisory text. Used only when CVSS PR is missing."""
    text = description or ""
    if not text.strip():
        return PRIV_UNKNOWN
    # Prefer unauth when both appear ("unauthenticated attacker gains authenticated access").
    if _UNAUTH_RE.search(text):
        return PRIV_UNAUTH
    if _HIGH_RE.search(text):
        return PRIV_HIGH
    if _LOW_RE.search(text):
        return PRIV_LOW
    return PRIV_UNKNOWN


def classify_privilege(
    *,
    vector: str | None = None,
    cvss_version: str | None = None,
    description: str | None = None,
    privileges_required: str | None = None,
    authentication: str | None = None,
) -> tuple[str, str, str | None]:
    """Return (privilege, source, pr_metric).

    privilege is unauth / low / high / unknown.
    source is 'cvss', 'text', or 'unknown'.
    pr_metric is 'N', 'L', 'H' when it came from CVSS, otherwise None.
    """
    metric = parse_pr_from_vector(vector, cvss_version) or parse_pr_from_fields(
        privileges_required, authentication
    )
    if metric in PR_TO_PRIV:
        return PR_TO_PRIV[metric], "cvss", metric
    text_priv = classify_from_text(description)
    if text_priv != PRIV_UNKNOWN:
        return text_priv, "text", None
    return PRIV_UNKNOWN, "unknown", None


def privilege_tag(
    privilege: str,
    pr_metric: str | None = None,
    source: str | None = None,
) -> str:
    """Short tag for a CVE line, e.g. '[PR:N unauth]' or '[unauth (text)]'."""
    priv = privilege if privilege in PRIVILEGE_VALUES else PRIV_UNKNOWN
    if pr_metric in PR_TO_PRIV:
        return f"[PR:{pr_metric} {priv}]"
    if source == "text":
        return f"[{priv} (text)]"
    if priv == PRIV_UNKNOWN:
        return "[PR:? unknown]"
    return f"[{priv}]"


def privilege_tag_from_record(rec: Any) -> str:
    """Build a tag from a FeedItem, CveRec, or item/match dict."""
    if rec is None:
        return privilege_tag(PRIV_UNKNOWN)
    if isinstance(rec, dict):
        priv = rec.get("privilege") or PRIV_UNKNOWN
        return privilege_tag(
            priv,
            rec.get("pr_metric"),
            rec.get("privilege_source"),
        )
    priv = getattr(rec, "privilege", None) or PRIV_UNKNOWN
    return privilege_tag(
        priv,
        getattr(rec, "pr_metric", None),
        getattr(rec, "privilege_source", None),
    )


def passes_priv_level(privilege: str, level: str) -> bool:
    if level == "all":
        return True
    if level == "unauth-or-unknown":
        return privilege in {PRIV_UNAUTH, PRIV_UNKNOWN}
    # default / "unauth": only clearly unauthenticated
    return privilege == PRIV_UNAUTH


def empty_counts() -> dict[str, int]:
    return {k: 0 for k in PRIVILEGE_VALUES}


def count_privileges(privileges: Iterable[str]) -> dict[str, int]:
    counts = empty_counts()
    for raw in privileges:
        key = raw if raw in counts else PRIV_UNKNOWN
        counts[key] += 1
    return counts


def dropped_breakdown(counts: dict[str, int], level: str) -> dict[str, int]:
    """How many of each non-kept privilege were dropped by this filter level."""
    if level == "all":
        return {}
    if level == "unauth-or-unknown":
        keys = (PRIV_LOW, PRIV_HIGH)
    else:
        keys = (PRIV_LOW, PRIV_HIGH, PRIV_UNKNOWN)
    return {k: int(counts.get(k) or 0) for k in keys}


def filter_note(counts: dict[str, int], level: str, *, dropped: int | None = None) -> str:
    """One-line summary of what the privilege filter kept and suppressed."""
    total = sum(counts.values())
    breakdown = dropped_breakdown(counts, level)
    if dropped is None:
        dropped = sum(breakdown.values())
    kept = total - dropped if total else 0
    if level == "all":
        return (
            "Privilege filter: off (all levels) — "
            f"{counts.get(PRIV_UNAUTH, 0)} unauth, {counts.get(PRIV_LOW, 0)} low, "
            f"{counts.get(PRIV_HIGH, 0)} high, {counts.get(PRIV_UNKNOWN, 0)} unknown "
            f"of {total} CVE(s) with a public PoC"
        )
    if level == "unauth-or-unknown":
        label = "unauthenticated or unknown"
    else:
        label = "unauthenticated only"
    parts = []
    if breakdown.get(PRIV_LOW):
        parts.append(f"{breakdown[PRIV_LOW]} low")
    if breakdown.get(PRIV_HIGH):
        parts.append(f"{breakdown[PRIV_HIGH]} high")
    if breakdown.get(PRIV_UNKNOWN) and level == "unauth":
        parts.append(f"{breakdown[PRIV_UNKNOWN]} unknown")
    detail = ", ".join(parts) if parts else "none"
    return (
        f"Privilege filter: {label} — kept {kept} of {total} CVE(s) with a public PoC; "
        f"dropped {dropped} that require privileges or have unknown PR ({detail})"
    )


def add_priv_level_argument(parser: Any) -> None:
    parser.add_argument(
        "--priv-level",
        choices=PRIV_LEVEL_CHOICES,
        default=DEFAULT_PRIV_LEVEL,
        help=(
            "Privilege filter (default: unauth). "
            "unauth = only CVEs with PR:N / no authentication required; "
            "unauth-or-unknown = also keep CVEs whose privilege level could not "
            "be determined; all = no privilege filter. Unknown is excluded by "
            "default so the feed stays conservative."
        ),
    )


def classify_item_dict(item: dict[str, Any]) -> dict[str, Any]:
    """Ensure a feed-item dict has privilege / privilege_source / pr_metric."""
    has_priv = item.get("privilege") in PRIVILEGE_VALUES
    has_source = item.get("privilege_source") in {"cvss", "text", "unknown"}
    if has_priv and has_source:
        return item
    priv, source, metric = classify_privilege(
        vector=item.get("vector"),
        cvss_version=item.get("cvss_version"),
        description=item.get("description") or item.get("description_one_line") or "",
        privileges_required=item.get("privileges_required"),
        authentication=item.get("authentication"),
    )
    item["privilege"] = priv
    item["privilege_source"] = source
    item["pr_metric"] = metric
    return item


def attach_privilege_stats(
    payload: dict[str, Any],
    counts: dict[str, int],
    level: str,
    kept: int,
) -> dict[str, Any]:
    breakdown = dropped_breakdown(counts, level)
    dropped = sum(breakdown.values()) if level != "all" else 0
    payload["priv_level"] = level
    payload["privilege_counts"] = counts
    payload["privilege_kept"] = kept
    payload["privilege_dropped"] = dropped
    payload["privilege_dropped_breakdown"] = breakdown
    payload["matched_after_privilege_filter"] = kept
    payload["privilege_note"] = filter_note(counts, level, dropped=dropped)
    return payload


def filter_feed_payload(payload: dict[str, Any], level: str) -> dict[str, Any]:
    """Classify items and apply the privilege filter to a cve-poc-feed JSON payload.

    If the payload was already filtered at the same --priv-level, it is returned
    unchanged (so digest → matcher does not double-drop). Counts always describe
    the pre-filter population when available.
    """
    if not isinstance(payload, dict):
        return payload
    already = (
        payload.get("priv_level") == level
        and "privilege_dropped" in payload
        and "privilege_counts" in payload
        and all(
            isinstance(it, dict) and it.get("privilege") in PRIVILEGE_VALUES
            for it in (payload.get("items") or [])
        )
    )
    if already:
        return payload

    items = [classify_item_dict(dict(it)) for it in (payload.get("items") or []) if isinstance(it, dict)]
    counts = count_privileges(it["privilege"] for it in items)
    if level == "all":
        kept_items = items
    else:
        kept_items = [it for it in items if passes_priv_level(it["privilege"], level)]
    out = dict(payload)
    out["items"] = kept_items
    attach_privilege_stats(out, counts, level, len(kept_items))
    return out


# Optional getter used when filtering object lists.
GetPriv = Callable[[Any], str]


def filter_records(records: list[Any], level: str, getter: GetPriv) -> tuple[list[Any], dict[str, int], int]:
    """Return (kept, counts_before, dropped)."""
    counts = count_privileges(getter(r) for r in records)
    if level == "all":
        return records, counts, 0
    kept = [r for r in records if passes_priv_level(getter(r), level)]
    return kept, counts, len(records) - len(kept)
