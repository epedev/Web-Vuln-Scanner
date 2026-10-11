"""Minimal Recon module that emits crawl_map.json for detection modules.

This is a lightweight producer so XSS integration has a real upstream contract.
It is intentionally conservative and does not expand scope beyond the seed URL.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from recon.schema import CRAWL_MAP_VERSION

logger = logging.getLogger("web_vuln.recon")

DEFAULT_UA = "WebVulnScanner/0.1 (+authorized-lab; recon)"


def run_recon(
    seed_url: str,
    *,
    session: requests.Session | None = None,
    timeout: float = 10.0,
    max_pages: int = 25,
    cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Crawl a single origin from seed_url and return a crawl_map dict."""
    parsed = urlparse(seed_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"invalid seed URL: {seed_url}")

    origin = f"{parsed.scheme}://{parsed.netloc}"
    sess = session or requests.Session()
    sess.headers.setdefault("User-Agent", DEFAULT_UA)
    if cookies:
        sess.cookies.update(cookies)

    queue = [seed_url]
    seen: set[str] = set()
    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    endpoints: list[dict[str, Any]] = []

    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        if not url.startswith(origin):
            logger.info("skipping out-of-origin URL during recon: %s", url)
            continue

        try:
            resp = sess.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            logger.warning("recon request failed for %s: %s", url, exc)
            continue

        final_url = str(resp.url)
        if not final_url.startswith(origin):
            logger.info("skipping out-of-origin redirect target: %s", final_url)
            continue

        content_type = resp.headers.get("Content-Type", "")
        page_entry: dict[str, Any] = {
            "url": final_url,
            "method": "GET",
            "status": resp.status_code,
            "content_type": content_type,
            "params": [],
            "forms": [],
            "links": [],
            "renders_from": [],
        }

        query = parse_qs(urlparse(final_url).query, keep_blank_values=True)
        for name, values in query.items():
            page_entry["params"].append(
                {
                    "name": name,
                    "value": values[0] if values else "",
                    "source": "query",
                    "input_type": "text",
                }
            )
            endpoints.append(
                {
                    "url": final_url.split("?", 1)[0],
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

        if "html" in content_type.lower() or resp.text.lstrip().startswith("<"):
            soup = BeautifulSoup(resp.text, "lxml")
            for a in soup.find_all("a", href=True):
                href = urljoin(final_url, a["href"])
                page_entry["links"].append(href)
                if href.startswith(origin) and href not in seen:
                    queue.append(href.split("#", 1)[0])

            for form in soup.find_all("form"):
                action = urljoin(final_url, form.get("action") or final_url)
                method = (form.get("method") or "GET").upper()
                enctype = (
                    form.get("enctype") or "application/x-www-form-urlencoded"
                ).lower()
                fields = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    fields.append(
                        {
                            "name": name,
                            "value": inp.get("value") or "",
                            "input_type": (inp.get("type") or inp.name or "text").lower(),
                            "required": inp.has_attr("required"),
                        }
                    )
                form_entry = {
                    "action": action,
                    "method": method,
                    "enctype": enctype,
                    "fields": fields,
                    "source_page": final_url,
                    "renders_to": [],
                }
                # Heuristic: comment/guestbook-style forms may render on listing pages.
                for link in page_entry["links"]:
                    lower = link.lower()
                    if any(k in lower for k in ("comment", "guest", "message", "post", "view")):
                        if link.startswith(origin):
                            form_entry["renders_to"].append(link)
                forms.append(form_entry)
                page_entry["forms"].append(
                    {"action": action, "method": method, "field_count": len(fields)}
                )
                endpoints.append(
                    {
                        "url": action,
                        "method": method,
                        "params": [
                            {
                                "name": f["name"],
                                "value": f["value"],
                                "source": "form",
                                "input_type": f["input_type"],
                            }
                            for f in fields
                            if f["input_type"] not in {"submit", "button", "image"}
                        ],
                        "enctype": enctype,
                        "source_page": final_url,
                        "renders_to": list(form_entry["renders_to"]),
                    }
                )

        pages.append(page_entry)

    return {
        "version": CRAWL_MAP_VERSION,
        "target": origin,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "pages": pages,
        "forms": forms,
        "endpoints": endpoints,
    }


def write_crawl_map(path: str, crawl_map: dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(crawl_map, fh, indent=2, ensure_ascii=False)
