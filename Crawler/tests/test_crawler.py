from unittest.mock import MagicMock, patch

import pytest

from crawler.config import CrawlerConfig
from crawler.engine import run_crawl
from crawler.schema import validate_crawl_map
from crawler.scope import ScopeController, ScopeError
from crawler_module import run_crawler_module


HTML_HOME = """<!DOCTYPE html><html><body>
<a href="/reflect?q=test">reflect</a>
<a href="/comment">comment</a>
<a href="/comments">comments</a>
<a href="http://evil.example/out">out</a>
</body></html>"""

HTML_REFLECT = """<!DOCTYPE html><html><body>
<form method="GET" action="/reflect"><input name="q" value=""><input type="submit" name="go" value="Go"></form>
</body></html>"""

HTML_COMMENT = """<!DOCTYPE html><html><body>
<form method="POST" action="/comment">
<textarea name="body"></textarea>
<input type="submit" name="submit" value="Post">
</form>
<a href="/comments">view comments</a>
</body></html>"""


def _resp(url: str, text: str, status: int = 200):
    r = MagicMock()
    r.status_code = status
    r.url = url
    r.is_redirect = False
    r.headers = {"Content-Type": "text/html; charset=utf-8"}
    r.encoding = "utf-8"
    r.iter_content.return_value = [text.encode("utf-8")]
    r.close = MagicMock()
    return r


def test_scope_rejects_out_of_origin():
    scope = ScopeController(["http://127.0.0.1:5001"], allow_loopback=True)
    with pytest.raises(ScopeError):
        scope.check("http://evil.example/")


def test_crawl_emits_valid_xss_schema():
    pages = {
        "http://127.0.0.1:5001/": HTML_HOME,
        "http://127.0.0.1:5001/reflect?q=test": HTML_REFLECT,
        "http://127.0.0.1:5001/comment": HTML_COMMENT,
        "http://127.0.0.1:5001/comments": "<html><body><ul></ul></body></html>",
    }

    def getter(url, **kwargs):
        # normalize without query for lookup of comment/comments
        base = url.split("#")[0]
        if base in pages:
            return _resp(base, pages[base])
        # try path only with query kept in url
        for key, html in pages.items():
            if base.startswith(key.split("?")[0]) and key.split("?")[0] in base:
                return _resp(base, html)
        return _resp(base, "<html></html>")

    cfg = CrawlerConfig(
        seed_url="http://127.0.0.1:5001/",
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
        max_pages=20,
    )
    with patch("requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()
        sess.get.side_effect = getter
        crawl_map = run_crawl(cfg)

    assert validate_crawl_map(crawl_map) == []
    assert crawl_map["version"] == "1.0"
    assert crawl_map["target"] == "http://127.0.0.1:5001"
    assert any("/reflect" in p["url"] for p in crawl_map["pages"])
    assert any(f.get("method") == "POST" for f in crawl_map["forms"])
    stored = [f for f in crawl_map["forms"] if f["method"] == "POST"]
    assert stored
    assert any("/comments" in u for u in stored[0].get("renders_to", []))
    # evil link never becomes a page
    assert not any("evil.example" in p["url"] for p in crawl_map["pages"])


def test_cli_requires_origin():
    from crawler_module import main

    assert main(["--seed", "http://127.0.0.1:5001/"]) == 2


def test_run_crawler_module_writes(tmp_path):
    html = "<html><body><a href='/a?x=1'>a</a></body></html>"

    def getter(url, **kwargs):
        return _resp(url.split("#")[0], html)

    out = tmp_path / "crawl_map.json"
    with patch("requests.Session") as Sess:
        sess = Sess.return_value
        sess.headers = {}
        sess.cookies = MagicMock()
        sess.get.side_effect = getter
        data = run_crawler_module(
            seed_url="http://127.0.0.1:5001/",
            allowed_origins=["http://127.0.0.1:5001"],
            allow_loopback=True,
            max_pages=5,
            output_path=str(out),
        )
    assert out.exists()
    assert data["pages"]
    assert validate_crawl_map(data) == []


def test_compatible_with_xss_input_adapter():
    """Ensure crawl_map loads through xss_module InputAdapter when available."""
    import sys
    from pathlib import Path

    xss_root = Path(__file__).resolve().parents[2]
    # workspace layout: web_vuln/xss ; GitHub: sibling xss_module
    candidates = [xss_root, xss_root / "xss_module", xss_root.parent / "xss_module"]
    loaded = False
    for root in candidates:
        if (root / "xss" / "input_adapter.py").exists():
            sys.path.insert(0, str(root))
            from xss.input_adapter import InputAdapter

            crawl_map = {
                "version": "1.0",
                "target": "http://127.0.0.1:5001",
                "pages": [
                    {
                        "url": "http://127.0.0.1:5001/reflect?q=1",
                        "method": "GET",
                        "params": [
                            {
                                "name": "q",
                                "value": "1",
                                "source": "query",
                                "input_type": "text",
                            }
                        ],
                    }
                ],
                "forms": [
                    {
                        "action": "http://127.0.0.1:5001/comment",
                        "method": "POST",
                        "fields": [
                            {"name": "body", "value": "", "input_type": "textarea"}
                        ],
                        "renders_to": ["http://127.0.0.1:5001/comments"],
                    }
                ],
                "endpoints": [],
            }
            points = InputAdapter().extract_input_points(crawl_map)
            assert any(p.parameter == "q" for p in points)
            assert any(p.parameter == "body" and p.renders_to for p in points)
            loaded = True
            break
    if not loaded:
        pytest.skip("xss input adapter not found on path")
