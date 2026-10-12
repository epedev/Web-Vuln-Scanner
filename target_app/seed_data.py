"""Reseed the VulnSight lab database with documented fake accounts."""

from __future__ import annotations

from database import init_db


def main() -> None:
    init_db()
    print("Seeded lab users: alice/alice123, bob/bobpass, admin/adminpass")


if __name__ == "__main__":
    main()
