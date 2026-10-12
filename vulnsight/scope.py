"""Central lab-first scope checks for the VulnSight CLI."""

from __future__ import annotations

from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target is outside the authorized assessment scope."""


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def require_lab_target(url: str, *, allow_external: bool = False) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ScopeError(f"invalid target URL: {url}")
    if parsed.scheme not in {"http", "https"}:
        raise ScopeError(f"unsupported URL scheme: {parsed.scheme}")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ScopeError(f"invalid target host: {url}")
    if not allow_external:
        if host not in LOOPBACK_HOSTS:
            raise ScopeError(
                "default lab mode only allows 127.0.0.1, localhost, or ::1. "
                "Pass --allow-external only for explicitly authorized non-lab targets."
            )
        if parsed.username or parsed.password:
            raise ScopeError("credentials in URL are not allowed")
        if parsed.scheme != "http":
            raise ScopeError("lab mode expects http:// loopback targets")
    return url.strip().rstrip("/")


def origin_of(url: str) -> str:
    p = urlparse(url)
    host = (p.hostname or "").lower()
    # Preserve bracket form for IPv6 literals in origins
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
        if p.port:
            netloc = f"{netloc}:{p.port}"
    else:
        netloc = p.netloc.lower()
    return f"{p.scheme.lower()}://{netloc}"
