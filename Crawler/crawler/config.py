"""Crawler runtime configuration."""

from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_UA = "WebVulnScanner/0.1 (+authorized-lab; crawler)"


@dataclass
class CrawlerConfig:
    seed_url: str
    allowed_origins: list[str] = field(default_factory=list)
    allow_loopback: bool = False
    allow_private: bool = False
    path_prefixes: list[str] = field(default_factory=lambda: ["/"])
    max_pages: int = 50
    timeout: float = 10.0
    connect_timeout: float = 5.0
    max_response_bytes: int = 1_000_000
    user_agent: str = DEFAULT_UA
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    same_origin_only: bool = True

    def validate(self) -> None:
        if not self.seed_url:
            raise ValueError("seed_url is required")
        if not self.allowed_origins:
            raise ValueError(
                "allowed_origins is required; seed URL alone is not authorization"
            )
        if self.max_pages < 1:
            raise ValueError("max_pages must be >= 1")
