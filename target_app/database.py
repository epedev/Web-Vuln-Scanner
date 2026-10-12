"""SQLite helpers for the VulnSight lab."""

from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "lab.db"


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(
            """
            DROP TABLE IF EXISTS users;
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                bio TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        users = [
            (1, "alice", "alice123", "alice@lab.local", "Alice bio", 0),
            (2, "bob", "bobpass", "bob@lab.local", "Bob bio", 0),
            (3, "admin", "adminpass", "admin@lab.local", "Admin bio", 1),
        ]
        conn.executemany(
            "INSERT INTO users (id, username, password, email, bio, is_admin) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            users,
        )
        conn.commit()
    finally:
        conn.close()
