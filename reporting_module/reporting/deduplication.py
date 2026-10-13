"""Conservative, evidence-preserving finding deduplication."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from reporting.schema import CanonicalFinding


def normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    # Sort query for equivalence; drop fragment
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query_items_sorted = sorted(query_items, key=lambda kv: (kv[0], kv[1]))
    query = urlencode(query_items_sorted)
    return urlunparse((scheme, netloc, path, "", query, ""))


def base_url(url: str) -> str:
    parsed = urlparse(normalize_url(url))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))


def vulnerability_class(vtype: str) -> str:
    v = vtype.lower().strip()
    if "stored" in v and "xss" in v:
        return "xss.stored"
    if "reflected" in v and "xss" in v:
        return "xss.reflected"
    # CSRF contains "cross-site" — classify before generic XSS.
    if "csrf" in v or "request forgery" in v:
        return "csrf"
    if "open redirect" in v or v == "open redirect":
        return "open_redirect"
    if "ssrf" in v or "server-side request" in v:
        return "ssrf"
    if "cryptographic" in v or "cleartext" in v:
        return "cryptographic_failure"
    if "xss" in v or ("cross-site" in v and "script" in v):
        return "xss"
    if "sql" in v:
        return "sqli"
    if "command" in v:
        return "command_injection"
    if "idor" in v or "access control" in v:
        return "access_control"
    if "misconfig" in v or "header" in v or "disclosure" in v:
        return "misconfiguration"
    return v


def _issue_distinguisher(finding: CanonicalFinding) -> str:
    """Keep distinct issues that share URL/parameter (e.g. different missing headers)."""
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    for key in (
        "missing_header",
        "header",
        "cookie",
        "probe_url",
        "probe_target",
        "missing_attributes",
    ):
        val = ev.get(key)
        if val is None or val == "":
            continue
        if isinstance(val, (list, tuple)):
            return f"{key}={','.join(str(x) for x in val)}".lower()
        return f"{key}={val}".lower()
    # Title separates same-class hygiene findings when evidence lacks a stable key.
    title = (finding.title or "").strip().lower()
    if title:
        return f"title={title}"
    return ""


def make_dedupe_key(finding: CanonicalFinding) -> str:
    return "|".join(
        [
            vulnerability_class(finding.vulnerability_type),
            finding.method.upper(),
            base_url(finding.url),
            (finding.parameter or "").lower(),
            (finding.location or "").lower(),
            _issue_distinguisher(finding),
        ]
    )


def _verification_rank(status: str) -> int:
    order = {
        "confirmed": 5,
        "probable": 4,
        "candidate": 3,
        "inconclusive": 2,
        "failed": 1,
        "unknown": 1,
        "not_attempted": 0,
        "not_applicable": 0,
        "rejected_safe": 0,
    }
    return order.get(status, 0)


def _score_key(finding: CanonicalFinding) -> tuple:
    score = finding.cvss_base_score if finding.cvss_base_score is not None else -1.0
    return (
        _verification_rank(finding.verification_status),
        score,
        finding.confidence,
    )


def deduplicate(findings: list[CanonicalFinding]) -> list[CanonicalFinding]:
    """Merge only when class/method/url/parameter match and verification is compatible."""
    buckets: dict[str, list[CanonicalFinding]] = {}
    for f in findings:
        key = make_dedupe_key(f)
        f.deduplication_key = key
        buckets.setdefault(key, []).append(f)

    merged: list[CanonicalFinding] = []
    for key, group in buckets.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        # Do not merge if verification states differ materially across confirmed vs candidate
        # unless all other fields match — keep the highest-evidence record as canonical
        # and attach provenance from others when same class/key.
        group_sorted = sorted(group, key=_score_key, reverse=True)
        primary = group_sorted[0]

        # If verification differs between confirmed and non-confirmed, still merge into
        # highest evidence but record sources — workbook wants one canonical entry.
        # However: different vulnerability classes already separated by key.
        # Refuse merge when evidence dicts imply different root causes via payload ids
        # AND verification both confirmed with different payloads — keep separate.
        if _should_keep_separate(group_sorted):
            merged.extend(group_sorted)
            continue

        for other in group_sorted[1:]:
            for sid in other.source_ids:
                if sid and sid not in primary.source_ids:
                    primary.source_ids.append(sid)
            for sf in other.source_files:
                if sf not in primary.source_files:
                    primary.source_files.append(sf)
            if other.source_module not in primary.warnings:
                primary.warnings.append(
                    f"merged equivalent finding from module={other.source_module} "
                    f"id={other.id} (key={key})"
                )
            # Prefer non-null CVSS from any member if primary unscored
            if primary.cvss_status != "scored" and other.cvss_status == "scored":
                primary.cvss_vector = other.cvss_vector
                primary.cvss_base_score = other.cvss_base_score
                primary.cvss_severity = other.cvss_severity
                primary.cvss_status = other.cvss_status
                primary.cvss_provenance = other.cvss_provenance
                if other.cvss_severity:
                    primary.severity = other.cvss_severity.lower()
                    if primary.severity == "none":
                        primary.severity = "info"
        merged.append(primary)
    return merged


def _should_keep_separate(group: list[CanonicalFinding]) -> bool:
    """Keep separate when reflected vs stored already handled by key; extra guard."""
    classes = {vulnerability_class(f.vulnerability_type) for f in group}
    if len(classes) > 1:
        return True
    # Different parameters already in key. If same key but conflicting confirmed evidence
    payloads = set()
    for f in group:
        pid = None
        if isinstance(f.evidence, dict):
            pid = f.evidence.get("payload_or_probe_id") or f.original.get(
                "payload_or_probe_id"
            )
        if pid:
            payloads.add(str(pid))
    confirmed = [f for f in group if f.verification_status == "confirmed"]
    if len(confirmed) >= 2 and len(payloads) >= 2:
        return True
    return False
