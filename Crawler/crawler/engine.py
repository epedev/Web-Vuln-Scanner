"""Same-origin HTML crawler that emits XSS-compatible crawl_map.json."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from crawler.config import CrawlerConfig
from crawler.schema import CRAWL_MAP_VERSION, validate_crawl_map
from crawler.scope import ScopeController, ScopeError

logger = logging.getLogger("web_vuln.crawler")

RENDER_HINTS = ("comment", "guest", "message", "post", "view", "list", "feed", "thread")


def _base(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def _strip_fragment(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))


def _origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme.lower()}://{p.netloc.lower()}"


class CrawlerEngine:
    def __init__(self, config: CrawlerConfig, session: requests.Session | None = None):
        config.validate()
        self.config = config
        self.scope = ScopeController(
            config.allowed_origins,
            allow_loopback=config.allow_loopback,
            allow_private=config.allow_private,
            path_prefixes=config.path_prefixes,
        )
        self.session = session or requests.Session()
        self.session.headers["User-Agent"] = config.user_agent
        if config.headers:
            self.session.headers.update(config.headers)
        if config.cookies:
            self.session.cookies.update(config.cookies)

    def crawl(self) -> dict[str, Any]:
        seed = self.scope.check(self.config.seed_url, purpose="seed")
        seed_origin = _origin_of(seed)
        queue = [seed]
        seen: set[str] = set()
        pages: list[dict[str, Any]] = []
        forms: list[dict[str, Any]] = []
        endpoints: list[dict[str, Any]] = []

        while queue and len(pages) < self.config.max_pages:
            url = queue.pop(0)
            key = _strip_fragment(url)
            if key in seen:
                continue
            seen.add(key)

            try:
                self.scope.check(url, purpose="crawl")
            except ScopeError as exc:
                logger.info("skip out-of-scope: %s", exc)
                continue

            if self.config.same_origin_only and _origin_of(url) != seed_origin:
                logger.info("skip different origin: %s", url)
                continue

            try:
                final, status, content_type, body = self._fetch(url)
            except (requests.RequestException, ScopeError) as exc:
                logger.warning("fetch failed %s: %s", url, exc)
                continue

            if self.config.same_origin_only and _origin_of(final) != seed_origin:
                continue

            page: dict[str, Any] = {
                "url": final,
                "method": "GET",
                "status": status,
                "content_type": content_type,
                "params": [],
                "forms": [],
                "links": [],
                "renders_from": [],
            }

            query = parse_qs(urlparse(final).query, keep_blank_values=True)
            for name, values in query.items():
                page["params"].append(
                    {
                        "name": name,
                        "value": values[0] if values else "",
                        "source": "query",
                        "input_type": "text",
                    }
                )
                endpoints.append(
                    {
                        "url": _base(final),
                        "method": "GET",
                        "params": [
                            {
                                "name": name,
                                "value": values[0] if values else "",
                                "source": "query",
                                "input_type": "text",
                            }
                        ],
                    }
                )

            if "html" in content_type.lower() or body.lstrip()[:1] == "<":
                try:
                    soup = BeautifulSoup(body, "lxml")
                except Exception:  # noqa: BLE001 — fall back when lxml unavailable
                    soup = BeautifulSoup(body, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = _strip_fragment(urljoin(final, a["href"]))
                    page["links"].append(href)
                    if href not in seen:
                        try:
                            self.scope.check(href, purpose="link")
                            if (
                                not self.config.same_origin_only
                                or _origin_of(href) == seed_origin
                            ):
                                queue.append(href)
                        except ScopeError:
                            pass

                for form_tag in soup.find_all("form"):
                    action = _strip_fragment(
                        urljoin(final, form_tag.get("action") or final)
                    )
                    method = (form_tag.get("method") or "GET").upper()
                    enctype = (
                        form_tag.get("enctype") or "application/x-www-form-urlencoded"
                    ).lower()
                    fields = []
                    for inp in form_tag.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if not name:
                            continue
                        fields.append(
                            {
                                "name": name,
                                "value": inp.get("value") or "",
                                "input_type": (
                                    inp.get("type") or inp.name or "text"
                                ).lower(),
                                "required": inp.has_attr("required"),
                            }
                        )
                    renders_to = self._guess_renders_to(page["links"], seed_origin)
                    form_entry = {
                        "action": action,
                        "method": method,
                        "enctype": enctype,
                        "fields": fields,
                        "source_page": final,
                        "renders_to": renders_to,
                    }
                    forms.append(form_entry)
                    page["forms"].append(
                        {
                            "action": action,
                            "method": method,
                            "field_count": len(fields),
                        }
                    )
                    endpoints.append(
                        {
                            "url": _base(action),
                            "method": method,
                            "params": [
                                {
                                    "name": f["name"],
                                    "value": f["value"],
                                    "source": "form",
                                    "input_type": f["input_type"],
                                }
                                for f in fields
                                if f["input_type"]
                                not in {"submit", "button", "image", "reset"}
                            ],
                            "enctype": enctype,
                            "source_page": final,
                            "renders_to": list(renders_to),
                        }
                    )

            pages.append(page)

        crawl_map = {
            "version": CRAWL_MAP_VERSION,
            "target": seed_origin,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "pages": pages,
            "forms": forms,
            "endpoints": self._dedupe_endpoints(endpoints),
        }
        errors = validate_crawl_map(crawl_map)
        if errors:
            raise ValueError("produced invalid crawl_map: " + "; ".join(errors))
        return crawl_map

    def _guess_renders_to(self, links: list[str], origin: str) -> list[str]:
        out: list[str] = []
        for link in links:
            lower = link.lower()
            if any(h in lower for h in RENDER_HINTS):
                try:
                    self.scope.check(link, purpose="renders_to")
                    if _origin_of(link) == origin:
                        out.append(link)
                except ScopeError:
                    continue
        seen: set[str] = set()
        uniq: list[str] = []
        for u in out:
            if u not in seen:
                seen.add(u)
                uniq.append(u)
        return uniq

    def _dedupe_endpoints(self, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple] = set()
        out: list[dict[str, Any]] = []
        for ep in endpoints:
            params = tuple(
                sorted(
                    (p.get("name"), p.get("source"))
                    for p in (ep.get("params") or [])
                    if p.get("name")
                )
            )
            key = (ep.get("url"), (ep.get("method") or "GET").upper(), params)
            if key in seen:
                continue
            seen.add(key)
            out.append(ep)
        return out

    def _fetch(self, url: str) -> tuple[str, int, str, str]:
        timeout = (self.config.connect_timeout, self.config.timeout)
        # Manual redirect handling for per-hop scope checks
        current = url
        history = 0
        while True:
            resp = self.session.get(
                current, timeout=timeout, allow_redirects=False, stream=True
            )
            if resp.is_redirect and history < 5:
                loc = resp.headers.get("Location")
                resp.close()
                if not loc:
                    break
                nxt = urljoin(str(resp.url), loc)
                self.scope.check(nxt, purpose="redirect")
                current = nxt
                history += 1
                continue

            chunks: list[bytes] = []
            total = 0
            try:
                for chunk in resp.iter_content(8192):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > self.config.max_response_bytes:
                        remain = self.config.max_response_bytes - (
                            total - len(chunk)
                        )
                        if remain > 0:
                            chunks.append(chunk[:remain])
                        break
                    chunks.append(chunk)
            finally:
                resp.close()
            raw = b"".join(chunks)
            encoding = resp.encoding or "utf-8"
            try:
                text = raw.decode(encoding, errors="replace")
            except LookupError:
                text = raw.decode("utf-8", errors="replace")
            return (
                str(resp.url),
                resp.status_code,
                resp.headers.get("Content-Type", ""),
                text,
            )


def run_crawl(
    config: CrawlerConfig, session: requests.Session | None = None
) -> dict[str, Any]:
    return CrawlerEngine(config, session=session).crawl()
