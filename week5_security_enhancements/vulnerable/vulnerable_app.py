"""QUARANTINED intentionally vulnerable baseline — DO NOT DEPLOY.

This file preserves the *before* implementation used for the Week 5 audit.
It contains textbook vulnerabilities on purpose so the attack simulations in
``tools/attack_demo.py`` can demonstrate impact locally and the hardened
``securenotes`` package can be tested against the same scenarios.

Never import this module from production code, never expose it on a network,
and never use it with real credentials or notes.
"""

from __future__ import annotations

import hashlib
import os
import pickle  # Vulnerability V-06: unsafe deserialization below.
import sqlite3
import time
from pathlib import Path


class VulnerableNotesApp:
    """A small, unsafe version of the same notes concept."""

    def __init__(self, db_path: str | Path, export_dir: str | Path) -> None:
        self.db_path = Path(db_path)
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)
        self.logs: list[str] = []  # Vulnerability V-10: secrets are logged.
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password_md5 TEXT,
                session_token TEXT
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT,
                body TEXT,
                tags TEXT
            );
            """
        )
        self.connection.commit()

    @staticmethod
    def _md5(password: str) -> str:
        # Vulnerability V-02: fast, unsalted password hashing.
        return hashlib.md5(password.encode()).hexdigest()

    def register(self, username: str, password: str) -> int:
        # Vulnerability V-11: no username/password policy or size limits.
        cursor = self.connection.execute(
            "INSERT INTO users (username, password_md5) VALUES (?, ?)",
            (username, self._md5(password)),
        )
        self.connection.commit()
        self.logs.append(f"registered username={username} password={password}")
        return int(cursor.lastrowid)

    def login(self, username: str, password: str) -> str:
        # Vulnerability V-01: user input is formatted directly into SQL.
        query = (
            "SELECT * FROM users "
            f"WHERE username = '{username}' AND password_md5 = '{self._md5(password)}'"
        )
        try:
            row = self.connection.execute(query).fetchone()
        except sqlite3.Error as exc:
            # Vulnerability V-10: raw database error and query leak to caller.
            raise ValueError(f"Database error {exc} while running {query}") from exc

        if row is None:
            # Vulnerabilities V-09/V-10: distinct, oracle-friendly errors.
            user_exists = self.connection.execute(
                f"SELECT id FROM users WHERE username = '{username}'"
            ).fetchone()
            if user_exists:
                raise ValueError("Wrong password for existing user")
            raise ValueError("User does not exist")

        # Vulnerability V-05: token is predictable and stored in raw form.
        token = f"session-{row['id']}-{int(time.time())}"
        self.connection.execute(
            "UPDATE users SET session_token = ? WHERE id = ?", (token, row["id"])
        )
        self.connection.commit()
        self.logs.append(f"login username={username} password={password} token={token}")
        return token

    def create_note(self, user_id: int, title: str, body: str, tags: str = "") -> int:
        # Vulnerability V-04: sensitive title/body/tags are plaintext at rest.
        cursor = self.connection.execute(
            "INSERT INTO notes (user_id, title, body, tags) VALUES (?, ?, ?, ?)",
            (user_id, title, body, tags),
        )
        self.connection.commit()
        # Vulnerability V-10: the complete private note body is also logged.
        self.logs.append(
            f"created note user_id={user_id} title={title} body={body}"
        )
        return int(cursor.lastrowid)

    def get_note(self, note_id: int) -> dict:
        # Vulnerability V-03: no ownership/authorization check (IDOR).
        row = self.connection.execute(
            "SELECT * FROM notes WHERE id = ?", (note_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"Note {note_id} does not exist")
        return dict(row)

    def search_notes(self, user_id: int, query: str) -> list[dict]:
        # Vulnerability V-01: search text is also interpolated into SQL.
        sql = (
            "SELECT * FROM notes "
            f"WHERE user_id = {user_id} AND (title LIKE '%{query}%' OR body LIKE '%{query}%')"
        )
        return [dict(row) for row in self.connection.execute(sql).fetchall()]

    def export_all_notes(self, filename: str) -> Path:
        # Vulnerability V-07: caller-controlled path traversal.
        target = self.export_dir / filename
        rows = self.connection.execute("SELECT title, body, tags FROM notes").fetchall()
        target.write_text("\n".join(f"{r['title']}: {r['body']}" for r in rows))
        return target

    def import_pickle(self, path: str | Path):
        # Vulnerability V-06: pickle can execute code during unpickling.
        with Path(path).open("rb") as handle:
            return pickle.load(handle)

    def backup_database(self, destination_name: str) -> int:
        # Vulnerability V-08: shell command injection through destination.
        command = f"cp {self.db_path} {self.export_dir}/{destination_name}"
        self.logs.append(f"backup command={command}")
        return os.system(command)

    def close(self) -> None:
        self.connection.close()
