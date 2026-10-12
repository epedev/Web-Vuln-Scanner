"""Credential / sensitive-value redaction for reports."""

from __future__ import annotations

import re
from typing import Any

REDACT = "[REDACTED]"

SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "session",
    "csrf",
    "x-api-key",
}

_HEADER_RE = re.compile(
    r"(?i)(authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*([^\r\n]+)"
)
_QUERY_RE = re.compile(
    r"(?i)([?&](?:password|passwd|token|secret|api_key|access_token)=)([^&]*)"
)


def redact_text(text: str) -> str:
    if not isinstance(text, str) or not text:
        return text
    text = _HEADER_RE.sub(lambda m: f"{m.group(1)}: {REDACT}", text)
    text = _QUERY_RE.sub(lambda m: f"{m.group(1)}{REDACT}", text)
    return text


def redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return redact_mapping(value)
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_mapping(data: dict[str, Any] | None) -> dict[str, Any]:
    if not data:
        return {}
    out: dict[str, Any] = {}
    for key, value in data.items():
        if str(key).lower() in SENSITIVE_KEYS:
            out[key] = REDACT
        else:
            out[key] = redact_value(value)
    return out
