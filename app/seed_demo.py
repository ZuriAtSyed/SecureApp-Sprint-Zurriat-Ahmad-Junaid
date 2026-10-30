"""
Seed the SecureShare DB with two demo users and files, for use in the
vulnerability demos (docs/SECURITY_IMPLEMENTATION.md). Lab use only.

Usage:  python3 seed_demo.py
"""
import sqlite3
from pathlib import Path

from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "secureshare.db"
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)


def main():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            display_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            uploaded_at TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
        """
    )

    users = [("alice", "AlicePassw0rd!"), ("bob", "BobPassw0rd!")]
    user_ids = {}
    for username, pw in users:
        cur = db.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row:
            user_ids[username] = row[0]
            continue
        cur = db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(pw)),
        )
        user_ids[username] = cur.lastrowid

    db.commit()

    # Alice's confidential file (the IDOR / CSRF / clickjacking "victim" target)
    alice_file = UPLOAD_DIR / "alice_confidential.txt"
    alice_file.write_text(
        "CONFIDENTIAL - Alice's payroll notes\n"
        "Salary review draft: do not share.\n"
    )
    existing = db.execute(
        "SELECT id FROM files WHERE stored_name = ?", (alice_file.name,)
    ).fetchone()
    if not existing:
        db.execute(
            "INSERT INTO files (owner_id, display_name, stored_name, title) "
            "VALUES (?, ?, ?, ?)",
            (user_ids["alice"], "payroll_notes.txt", alice_file.name,
             "Alice Q3 payroll notes"),
        )

    # Bob's own file (the attacker's legitimate file, for comparison)
    bob_file = UPLOAD_DIR / "bob_notes.txt"
    bob_file.write_text("Bob's grocery list.\n")
    existing = db.execute(
        "SELECT id FROM files WHERE stored_name = ?", (bob_file.name,)
    ).fetchone()
    if not existing:
        db.execute(
            "INSERT INTO files (owner_id, display_name, stored_name, title) "
            "VALUES (?, ?, ?, ?)",
            (user_ids["bob"], "notes.txt", bob_file.name, "Bob's notes"),
        )

    db.commit()
    db.close()
    print("Seed complete. Users: alice/AlicePassw0rd!  bob/BobPassw0rd!")


if __name__ == "__main__":
    main()
