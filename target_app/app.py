#!/usr/bin/env python3
"""VulnSight deliberately vulnerable Flask lab (loopback only).

WARNING: Intentional vulnerabilities for authorized training. Do not expose publicly.
"""

from __future__ import annotations

import html
import os
import re
from urllib.parse import urlparse

from flask import Flask, redirect, render_template_string, request, session

try:
    from target_app.database import DB_PATH, connect, init_db
except ImportError:  # running as script: python target_app/app.py
    from database import DB_PATH, connect, init_db

HOST = os.environ.get("VULNSIGHT_LAB_HOST", "127.0.0.1")
PORT = int(os.environ.get("VULNSIGHT_LAB_PORT", "5001"))

app = Flask(__name__)
app.secret_key = "vulnsight-lab-only-not-for-production"

COMMENTS: list[str] = []

NAV = """
<nav style="margin-bottom:1rem">
  <a href="/">Home</a> |
  <a href="/reflect?q=demo">Reflect XSS</a> |
  <a href="/encoded?q=demo">Encoded</a> |
  <a href="/attr?q=demo">Attr</a> |
  <a href="/js?q=demo">JS</a> |
  <a href="/comment">Comment</a> |
  <a href="/comments">Comments</a> |
  <a href="/login">Login</a> |
  <a href="/ping">Ping</a> |
  <a href="/profile/1">Profile 1</a> |
  <a href="/admin">Admin</a>
</nav>
"""

BASE = """<!DOCTYPE html>
<html><head><title>{{ title }} — VulnSight Lab</title></head>
<body>
""" + NAV + """
<h1>{{ title }}</h1>
{{ body|safe }}
</body></html>
"""


def page(title: str, body: str) -> str:
    return render_template_string(BASE, title=title, body=body)


@app.before_request
def _reseed_if_needed() -> None:
    # Ensure DB exists for fresh clones
    if not DB_PATH.exists():
        init_db()


def reset_lab_state() -> dict[str, str]:
    """Reseed SQLite users and clear in-memory stored-XSS comments."""
    global COMMENTS
    COMMENTS = []
    init_db()
    return {
        "status": "ok",
        "message": "Lab reset: users reseeded, stored comments cleared",
    }


@app.post("/_lab/reset")
def lab_reset():
    """Demo helper: restore a clean lab state before a repeat presentation."""
    result = reset_lab_state()
    return page("Lab Reset", f"<p>{html.escape(result['message'])}</p>")


@app.get("/")
def home():
    return page(
        "VulnSight Lab",
        "<p><strong>Authorized local training only.</strong> "
        "Planted vulnerabilities are intentional.</p>"
        "<ul>"
        "<li>XSS: <a href='/reflect?q=demo'>/reflect?q=</a>, <a href='/comment'>/comment</a></li>"
        "<li>SQLi: <a href='/login'>/login</a></li>"
        "<li>Command injection (simulated): <a href='/ping'>/ping</a></li>"
        "<li>IDOR: <a href='/profile/1'>/profile/&lt;id&gt;</a></li>"
        "<li>Broken access control: <a href='/admin'>/admin</a></li>"
        "</ul>"
        "<p>Secure counterparts: /encoded?q=, /login-secure, /profile-secure/&lt;id&gt;, /admin-secure</p>"
        "<p class='muted'>Reset before a repeat demo: "
        "<code>curl -X POST http://127.0.0.1:5001/_lab/reset</code></p>",
    )


# --- XSS ---
@app.get("/reflect")
def reflect():
    q = request.args.get("q", "")
    # VULNERABLE reflected XSS
    return page("Reflect", f"<div>Result: {q}</div>")


@app.get("/encoded")
def encoded():
    q = request.args.get("q", "")
    return page("Encoded", f"<div>Result: {html.escape(q)}</div>")


@app.get("/attr")
def attr():
    q = request.args.get("q", "")
    return page("Attribute", f'<input type="text" value="{q}">')


@app.get("/js")
def js():
    q = request.args.get("q", "")
    return page("JS", f"<script>const value = '{q}';</script><p>see script</p>")


@app.get("/url")
def url_ctx():
    q = request.args.get("q", "")
    return page("URL", f'<a href="{html.escape(q, quote=True)}">link</a>')


@app.get("/inert")
def inert():
    q = request.args.get("q", "")
    return page("Inert", f"<!-- user:{q} --><p>No visible reflection</p>")


@app.get("/multi")
def multi():
    a = request.args.get("a", "")
    b = request.args.get("b", "")
    return page("Multi", f"<div>A={a}</div><div>B={html.escape(b)}</div>")


@app.route("/comment", methods=["GET", "POST"])
def comment():
    if request.method == "GET":
        return page(
            "Comment",
            '<form method="POST" action="/comment">'
            '<textarea name="body"></textarea>'
            '<input type="submit" name="submit" value="Post">'
            "</form>",
        )
    COMMENTS.append(request.form.get("body", ""))
    return redirect("/comments")


@app.get("/comments")
def comments():
    items = "".join(f"<li>{c}</li>" for c in COMMENTS)
    return page("Comments", f"<ul id='comments'>{items}</ul>")


# --- Auth / SQLi ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page(
            "Login",
            '<form method="POST">'
            'User: <input name="username">'
            ' Pass: <input name="password" type="password">'
            '<input type="submit" value="Login">'
            "</form>",
        )
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = connect()
    try:
        # VULNERABLE: string-concatenated SQL
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{password}'"
        )
        try:
            row = conn.execute(query).fetchone()
        except Exception as exc:  # noqa: BLE001 — surface DB errors for error-based SQLi demos
            return page("Login", f"<p>sqlite3.OperationalError: {html.escape(str(exc))}</p>"), 500
    finally:
        conn.close()
    if row:
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        session["is_admin"] = bool(row["is_admin"])
        return redirect("/")
    return page("Login", "<p>Invalid credentials</p>")


@app.route("/login-secure", methods=["GET", "POST"])
def login_secure():
    if request.method == "GET":
        return page(
            "Secure Login",
            '<form method="POST">'
            'User: <input name="username">'
            ' Pass: <input name="password" type="password">'
            '<input type="submit" value="Login">'
            "</form>",
        )
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = connect()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
    finally:
        conn.close()
    if row:
        session["user_id"] = row["id"]
        session["username"] = row["username"]
        session["is_admin"] = bool(row["is_admin"])
        return redirect("/")
    return page("Secure Login", "<p>Invalid credentials</p>")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")


# --- Command injection (SIMULATED — no shell execution) ---
@app.route("/ping", methods=["GET", "POST"])
def ping():
    if request.method == "GET":
        return page(
            "Ping",
            "<p>Educational simulation: does not execute a real shell.</p>"
            '<form method="POST">Host: <input name="host" value="127.0.0.1">'
            '<input type="submit" value="Ping"></form>',
        )
    host = request.form.get("host", "")
    # Simulate unsafe shell concatenation without invoking the OS shell.
    # If input contains `; printf TOKEN`, echo TOKEN into the response.
    output = f"PING {host.split(';')[0].strip()} simulated ok\n"
    match = re.search(r";\s*printf\s+([A-Za-z0-9_]+)", host)
    if match:
        output += match.group(1)
    return page("Ping", f"<pre>{html.escape(output)}</pre>")


# --- Access control ---
@app.get("/profile/<int:user_id>")
def profile(user_id: int):
    if "user_id" not in session:
        return redirect("/login")
    conn = connect()
    try:
        # VULNERABLE IDOR: no ownership check
        row = conn.execute(
            "SELECT id, username, email, bio FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return page("Profile", "<p>Not found</p>"), 404
    body = (
        f"<p>id={row['id']}</p><p>user={html.escape(row['username'])}</p>"
        f"<p>email={html.escape(row['email'])}</p>"
        f"<p>bio={html.escape(row['bio'])}</p>"
    )
    return page("Profile", body)


@app.get("/profile-secure/<int:user_id>")
def profile_secure(user_id: int):
    if "user_id" not in session:
        return redirect("/login")
    if session["user_id"] != user_id and not session.get("is_admin"):
        return page("Profile", "<p>Forbidden</p>"), 403
    conn = connect()
    try:
        row = conn.execute(
            "SELECT id, username, email, bio FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return page("Profile", "<p>Not found</p>"), 404
    body = (
        f"<p>id={row['id']}</p><p>user={html.escape(row['username'])}</p>"
        f"<p>email={html.escape(row['email'])}</p>"
    )
    return page("Secure Profile", body)


@app.get("/admin")
def admin():
    if "user_id" not in session:
        return redirect("/login")
    # VULNERABLE: any authenticated user
    conn = connect()
    try:
        rows = conn.execute("SELECT id, username, is_admin FROM users").fetchall()
    finally:
        conn.close()
    items = "".join(
        f"<li>{r['id']} {html.escape(r['username'])} admin={r['is_admin']}</li>"
        for r in rows
    )
    return page("Admin", f"<ul>{items}</ul>")


@app.get("/admin-secure")
def admin_secure():
    if "user_id" not in session:
        return redirect("/login")
    if not session.get("is_admin"):
        return page("Admin", "<p>Forbidden</p>"), 403
    return page("Secure Admin", "<p>Admin-only panel</p>")


def main() -> None:
    init_db()
    # Bind loopback by default
    if HOST not in {"127.0.0.1", "localhost"}:
        raise SystemExit("Refusing to bind non-loopback host without explicit review")
    print(f"VulnSight lab on http://{HOST}:{PORT} (loopback only)")
    app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
