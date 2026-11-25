#!/usr/bin/env python3
"""Authoritative CWE → vulnerability-type labels, shared by the feed and ranker.

Used for the description-accuracy pass: instead of guessing a bug class from
prose, the pipeline pulls the vulnerability type from the NVD CWE assignment,
which is authoritative. Prose parsing is only a fallback, and when neither the
CWE nor the text yields a confident class the finding is flagged rather than
given an invented description.
"""

from __future__ import annotations

import re

# CWE id -> short, plain-English vulnerability type. Conservative: only CWEs
# whose mapping to a user-facing bug class is unambiguous.
CWE_LABELS: dict[str, str] = {
    "CWE-20": "input validation",
    "CWE-22": "path traversal",
    "CWE-23": "path traversal",
    "CWE-24": "path traversal",
    "CWE-35": "path traversal",
    "CWE-59": "link following",
    "CWE-73": "external file control",
    "CWE-78": "OS command injection",
    "CWE-79": "XSS",
    "CWE-80": "XSS",
    "CWE-83": "XSS",
    "CWE-88": "argument injection",
    "CWE-89": "SQL injection",
    "CWE-90": "LDAP injection",
    "CWE-91": "XML injection",
    "CWE-94": "code injection",
    "CWE-95": "code injection (eval)",
    "CWE-96": "code injection",
    "CWE-98": "PHP file inclusion",
    "CWE-113": "HTTP header injection",
    "CWE-116": "improper output encoding",
    "CWE-120": "buffer overflow",
    "CWE-122": "heap overflow",
    "CWE-125": "out-of-bounds read",
    "CWE-134": "format string",
    "CWE-190": "integer overflow",
    "CWE-200": "information disclosure",
    "CWE-201": "information disclosure",
    "CWE-209": "information disclosure (errors)",
    "CWE-250": "excessive privileges",
    "CWE-256": "plaintext credential storage",
    "CWE-269": "privilege management",
    "CWE-284": "improper access control",
    "CWE-285": "improper authorization",
    "CWE-287": "improper authentication",
    "CWE-288": "auth bypass (alternate path)",
    "CWE-290": "auth bypass (spoofing)",
    "CWE-294": "auth bypass (capture-replay)",
    "CWE-295": "improper certificate validation",
    "CWE-306": "missing authentication",
    "CWE-307": "brute-force (no lockout)",
    "CWE-311": "missing encryption",
    "CWE-319": "cleartext transmission",
    "CWE-320": "key management",
    "CWE-321": "hard-coded key",
    "CWE-322": "key exchange without auth",
    "CWE-326": "weak encryption",
    "CWE-327": "broken crypto algorithm",
    "CWE-330": "insufficient randomness",
    "CWE-346": "origin validation error",
    "CWE-352": "CSRF",
    "CWE-367": "TOCTOU race condition",
    "CWE-384": "session fixation",
    "CWE-400": "resource exhaustion (DoS)",
    "CWE-401": "memory leak",
    "CWE-415": "double free",
    "CWE-416": "use-after-free",
    "CWE-425": "forced browsing",
    "CWE-426": "untrusted search path",
    "CWE-434": "unrestricted file upload",
    "CWE-444": "HTTP request smuggling",
    "CWE-470": "unsafe reflection",
    "CWE-476": "null pointer dereference",
    "CWE-502": "insecure deserialization",
    "CWE-521": "weak password requirements",
    "CWE-522": "insufficiently protected credentials",
    "CWE-537": "information disclosure",
    "CWE-552": "files accessible to external parties",
    "CWE-565": "reliance on cookies without validation",
    "CWE-601": "open redirect",
    "CWE-611": "XXE",
    "CWE-613": "insufficient session expiration",
    "CWE-620": "unverified password change",
    "CWE-639": "IDOR / authorization bypass",
    "CWE-640": "weak password recovery",
    "CWE-732": "incorrect permission assignment",
    "CWE-776": "XML entity expansion",
    "CWE-787": "out-of-bounds write",
    "CWE-798": "hard-coded credentials",
    "CWE-862": "missing authorization",
    "CWE-863": "incorrect authorization",
    "CWE-915": "mass assignment",
    "CWE-916": "weak password hash",
    "CWE-918": "SSRF",
    "CWE-1021": "clickjacking",
    "CWE-1236": "formula injection",
    "CWE-1333": "ReDoS",
}

# CWEs that are too abstract / structural to describe a user-facing bug class.
# If only these are present we prefer the prose or flag the finding.
VAGUE_CWES = {
    "CWE-noinfo", "CWE-other", "CWE-404", "CWE-664", "CWE-693", "CWE-707",
    "CWE-710", "CWE-1284", "CWE-345", "CWE-704",
}


def cwe_types(cwes: list[str] | None) -> list[str]:
    """Ordered, de-duplicated plain-English types for the given CWE ids."""
    out: list[str] = []
    for cwe in cwes or []:
        label = CWE_LABELS.get(str(cwe).upper())
        if label and label not in out:
            out.append(label)
    return out


def primary_cwe_type(cwes: list[str] | None) -> str | None:
    """The first mappable, non-vague CWE label, or None."""
    types = cwe_types(cwes)
    return types[0] if types else None


def has_mappable_cwe(cwes: list[str] | None) -> bool:
    return bool(cwe_types(cwes))


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)


def looks_like_real_description(text: str | None) -> bool:
    """True when NVD text is a genuine description, not a placeholder."""
    t = (text or "").strip()
    if len(t) < 25:
        return False
    low = t.lower()
    placeholders = (
        "rejected reason",
        "do not use this candidate",
        "** reserved **",
        "is awaiting reanalysis",
        "** rejected **",
    )
    return not any(p in low for p in placeholders)
