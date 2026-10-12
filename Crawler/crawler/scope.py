"""Fail-closed crawl scope — never expand beyond configured origins."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


class ScopeError(Exception):
    pass


METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}


def normalize_origin(origin: str) -> str:
    origin = origin.strip().rstrip("/")
    parsed = urlparse(origin if "://" in origin else f"http://{origin}")
    if not parsed.scheme or not parsed.netloc:
        raise ScopeError(f"invalid origin: {origin}")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


class ScopeController:
    def __init__(
        self,
        allowed_origins: list[str],
        *,
        allow_loopback: bool = False,
        allow_private: bool = False,
        path_prefixes: list[str] | None = None,
    ):
        self.allowed_origins = [normalize_origin(o) for o in allowed_origins]
        self.allow_loopback = allow_loopback
        self.allow_private = allow_private
        self.path_prefixes = path_prefixes or ["/"]

    def check(self, url: str, *, purpose: str = "crawl") -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ScopeError(f"{purpose}: invalid URL {url!r}")
        origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        if origin not in self.allowed_origins:
            raise ScopeError(f"{purpose}: origin {origin} not allowed")
        host = (parsed.hostname or "").lower().strip("[]")
        if host in METADATA_HOSTS:
            raise ScopeError(f"{purpose}: metadata host blocked")
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_loopback:
                if not self.allow_loopback:
                    raise ScopeError(
                        f"{purpose}: loopback blocked (use --allow-loopback)"
                    )
            elif ip.is_link_local or ip.is_private:
                if not self.allow_private:
                    raise ScopeError(f"{purpose}: private/link-local blocked")
        except ValueError:
            if host in {"localhost", "localhost.localdomain"} and not self.allow_loopback:
                raise ScopeError(f"{purpose}: loopback hostname blocked")
        path = parsed.path or "/"
        if not any(path.startswith(p) for p in self.path_prefixes):
            raise ScopeError(f"{purpose}: path {path!r} outside prefixes")
        return url
