#!/usr/bin/env python3
"""VulnSight crawler entry point — emits XSS-compatible crawl_map.json.

CLI:
  python crawler_module.py --seed http://127.0.0.1:5001/ \\
      --origin http://127.0.0.1:5001 --allow-loopback -o crawl_map.json

Programmatic:
  from crawler_module import run_crawler_module
  crawl_map = run_crawler_module(seed_url=..., allowed_origins=[...], allow_loopback=True)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from crawler.config import CrawlerConfig
from crawler.engine import run_crawl
from crawler.scope import normalize_origin


def run_crawler_module(
    *,
    seed_url: str,
    allowed_origins: list[str] | None = None,
    allow_loopback: bool = False,
    allow_private: bool = False,
    path_prefixes: list[str] | None = None,
    max_pages: int = 50,
    timeout: float = 10.0,
    output_path: str | None = None,
    cookies: dict[str, str] | None = None,
    verbose: bool = False,
) -> dict[str, Any]:
    """Crawl and return a crawl_map dict (optionally write JSON)."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    origins = list(allowed_origins or [])
    if not origins:
        # Convenience only when caller forgot — still requires explicit flag in CLI.
        p = urlparse(seed_url)
        origins = [f"{p.scheme}://{p.netloc}"]
    origins = [normalize_origin(o) for o in origins]

    config = CrawlerConfig(
        seed_url=seed_url,
        allowed_origins=origins,
        allow_loopback=allow_loopback,
        allow_private=allow_private,
        path_prefixes=path_prefixes or ["/"],
        max_pages=max_pages,
        timeout=timeout,
        cookies=cookies or {},
    )
    crawl_map = run_crawl(config)
    if output_path:
        Path(output_path).write_text(
            json.dumps(crawl_map, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    return crawl_map


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Authorized same-origin crawler for VulnSight. "
            "Writes crawl_map.json for xss_module. Requires explicit --origin."
        )
    )
    p.add_argument("--seed", required=True, help="Seed URL to start crawling")
    p.add_argument(
        "--origin",
        action="append",
        default=[],
        help="Allowed origin (repeatable), e.g. http://127.0.0.1:5001",
    )
    p.add_argument("--allow-loopback", action="store_true")
    p.add_argument("--allow-private", action="store_true")
    p.add_argument(
        "--path-prefix",
        action="append",
        default=[],
        help="Allowed path prefix (repeatable). Default: /",
    )
    p.add_argument("--max-pages", type=int, default=50)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("-o", "--output", default="crawl_map.json")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.origin:
        print(
            "error: explicit --origin is required "
            "(seed URL alone is not authorization)",
            file=sys.stderr,
        )
        return 2
    try:
        crawl_map = run_crawler_module(
            seed_url=args.seed,
            allowed_origins=args.origin,
            allow_loopback=args.allow_loopback,
            allow_private=args.allow_private,
            path_prefixes=args.path_prefix or ["/"],
            max_pages=args.max_pages,
            timeout=args.timeout,
            output_path=args.output,
            verbose=args.verbose,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"wrote crawl_map with {len(crawl_map.get('pages', []))} pages, "
        f"{len(crawl_map.get('forms', []))} forms, "
        f"{len(crawl_map.get('endpoints', []))} endpoints -> {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
