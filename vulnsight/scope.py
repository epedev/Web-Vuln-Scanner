"""Central lab-first scope checks for the VulnSight CLI."""

from __future__ import annotations

from urllib.parse import urlparse


class ScopeError(Exception):
    pass


def require_lab_target(url: str, *, allow_external: bool = False) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ScopeError(f"invalid target URL: {url}")
    host = (parsed.hostname or "").lower()
    if not allow_external:
        if host not in {"127.0.0.1", "localhost"}:
            raise ScopeError(
                "default lab mode only allows 127.0.0.1/localhost. "
                "Pass --allow-external only for explicitly authorized non-lab targets."
            )
        if parsed.username or parsed.password:
            raise ScopeError("credentials in URL are not allowed")
        if parsed.scheme != "http":
            raise ScopeError("lab mode expects http://127.0.0.1 targets")
    return url.rstrip("/")


def origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme.lower()}://{p.netloc.lower()}"
