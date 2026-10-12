"""Vulnerability-class remediation guidance."""

from __future__ import annotations


def remediation_for(vulnerability_type: str, location: str | None = None) -> str:
    v = vulnerability_type.lower()
    loc = (location or "").lower()

    if "xss" in v or "cross-site" in v:
        parts = [
            "Encode untrusted data for the output context before rendering.",
            "Prefer framework auto-escaping; avoid inserting untrusted HTML into the DOM.",
            "Apply a strict Content-Security-Policy as defense-in-depth.",
        ]
        if "attr" in loc:
            parts.insert(
                0,
                "For HTML attributes, use context-appropriate attribute encoding "
                "and never place untrusted data in event-handler attributes.",
            )
        elif "javascript" in loc or "js_" in loc:
            parts.insert(
                0,
                "For JavaScript string contexts, use JS-specific escaping or "
                "JSON serialization; avoid string concatenation into scripts.",
            )
        elif "html_body" in loc or "body" in loc:
            parts.insert(
                0,
                "For HTML body context, HTML-encode `<`, `>`, `&`, quotes before output.",
            )
        return " ".join(parts)

    if "sql" in v:
        return (
            "Use parameterized queries / prepared statements for all database access. "
            "Never concatenate untrusted input into SQL. Avoid returning raw database "
            "errors to clients; apply least-privilege DB accounts."
        )

    if "command" in v:
        return (
            "Avoid shell execution. Prefer argument arrays with shell=False, "
            "strict allowlists for inputs, and drop unnecessary OS privileges."
        )

    if "misconfig" in v or "header" in v:
        return (
            "Apply the missing security control specifically identified by the finding "
            "(for example set Content-Security-Policy, X-Content-Type-Options, "
            "Strict-Transport-Security, or secure cookie flags). Verify configuration "
            "in staging before production rollout."
        )

    return (
        "Validate and sanitize untrusted input, apply least privilege, and remediate "
        "according to the concrete weakness described in the finding evidence."
    )
