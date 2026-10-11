#!/usr/bin/env python3
"""Self-authored intentionally vulnerable lab app for XSS module testing.

Bind to loopback only. Do not expose this application on a public network.
Vulnerable behaviors are deliberate and documented per route.
"""

from __future__ import annotations

import html
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

HOST = "127.0.0.1"
PORT = 5001

# In-memory stored comments for stored-XSS lab route.
COMMENTS: list[str] = []


def _page(title: str, body: str) -> bytes:
    doc = f"""<!DOCTYPE html>
<html><head><title>{title}</title></head>
<body>
<nav>
  <a href="/">Home</a> |
  <a href="/reflect">Reflect</a> |
  <a href="/encoded">Encoded</a> |
  <a href="/attr">Attr</a> |
  <a href="/js">JS</a> |
  <a href="/url">URL</a> |
  <a href="/comment">Comment</a> |
  <a href="/comments">Comments</a> |
  <a href="/inert">Inert</a>
</nav>
<h1>{title}</h1>
{body}
</body></html>
"""
    return doc.encode("utf-8")


def application(environ, start_response):
    path = environ.get("PATH_INFO") or "/"
    method = environ.get("REQUEST_METHOD", "GET").upper()
    qs = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)

    def get_param(name: str, default: str = "") -> str:
        vals = qs.get(name)
        return vals[0] if vals else default

    def read_form() -> dict[str, str]:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        raw = environ["wsgi.input"].read(length) if length else b""
        parsed = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=True)
        return {k: (v[0] if v else "") for k, v in parsed.items()}

    # --- Routes ---
    if path == "/":
        body = "<p>XSS lab fixture. Authorized local testing only.</p>"
        data = _page("XSS Lab", body)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    if path == "/reflect":
        # VULNERABLE: reflected HTML body, unencoded
        q = get_param("q")
        body = f"<div>Result: {q}</div>"
        data = _page("Reflect", body)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    if path == "/encoded":
        # SAFE: HTML-encoded body reflection
        q = get_param("q")
        body = f"<div>Result: {html.escape(q)}</div>"
        data = _page("Encoded", body)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    if path == "/attr":
        # VULNERABLE: attribute reflection without encoding
        q = get_param("q")
        body = f'<input type="text" value="{q}">'
        data = _page("Attribute", body)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    if path == "/js":
        # VULNERABLE: JS string context
        q = get_param("q")
        body = f"<script>const value = '{q}';</script><p>see script</p>"
        data = _page("JS", body)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    if path == "/url":
        # Ambiguous/URL context — reflection in href
        q = get_param("q")
        body = f'<a href="{html.escape(q, quote=True)}">link</a>'
        data = _page("URL", body)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    if path == "/inert":
        # Marker may reflect inside HTML comment — should not be confirmed XSS
        q = get_param("q")
        body = f"<!-- user:{q} --><p>No visible reflection</p>"
        data = _page("Inert", body)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    if path == "/comment" and method == "GET":
        body = """
<form method="POST" action="/comment">
  <textarea name="body"></textarea>
  <input type="submit" name="submit" value="Post">
</form>
"""
        data = _page("Comment form", body)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    if path == "/comment" and method == "POST":
        # VULNERABLE stored XSS sink when rendered on /comments
        form = read_form()
        COMMENTS.append(form.get("body", ""))
        start_response(
            "302 Found",
            [("Location", "/comments"), ("Content-Type", "text/plain")],
        )
        return [b"redirect"]

    if path == "/comments":
        # VULNERABLE: stored comments rendered unencoded
        items = "".join(f"<li>{c}</li>" for c in COMMENTS)
        body = f"<ul id='comments'>{items}</ul>"
        data = _page("Comments", body)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    if path == "/redirect-external":
        start_response("302 Found", [("Location", "http://example.com/")])
        return [b"redirect"]

    if path == "/multi":
        a = get_param("a")
        b = get_param("b")
        body = f"<div>A={a}</div><div>B={html.escape(b)}</div>"
        data = _page("Multi", body)
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"not found"]


def main() -> None:
    with make_server(HOST, PORT, application) as httpd:
        print(f"XSS lab listening on http://{HOST}:{PORT} (loopback only)")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
