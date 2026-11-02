"""SQLite storage for SecureNotes.

Security properties in this layer:

* every value is sent through a bound SQL parameter (``?``), never formatted
  into SQL text;
* foreign keys are enabled and user deletion cascades to owned records;
* the database directory/file are restricted to owner access on POSIX;
* session tokens are represented only by a hash in the schema;
* note title/body/tags columns contain Fernet ciphertext, not plaintext.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from .errors import StorageError

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    key_salt TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title_ciphertext TEXT NOT NULL,
    body_ciphertext TEXT NOT NULL,
    tags_ciphertext TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    event TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id, id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_events(user_id, created_at);
"""


class Database:
    """Small SQLite wrapper used by auth and note services."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.connection = sqlite3.connect(self.path)
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA journal_mode = WAL")
            self.connection.executescript(SCHEMA)
            self.connection.commit()
            self._restrict_permissions()
        except (OSError, sqlite3.Error) as exc:
            raise StorageError("The secure database could not be opened.") from exc

    def _restrict_permissions(self, *, chmod_parent: bool = False) -> None:
        """Apply owner-only permissions where the platform supports them.

        A parent directory is tightened only when SecureNotes created it.
        This avoids surprising side effects such as changing the mode of a
        user's current/project directory when ``--db notes.db`` is used.
        """
        try:
            if chmod_parent and self.path.parent not in (Path(""), Path(".")):
                os.chmod(self.path.parent, 0o700)
            os.chmod(self.path, 0o600)
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{self.path}{suffix}")
                if sidecar.exists():
                    os.chmod(sidecar, 0o600)
        except OSError:
            # Windows and some filesystems do not implement POSIX modes.
            # Encryption and authentication remain in force.
            pass

    def execute(self, sql: str, parameters: tuple = ()) -> sqlite3.Cursor:
        """Execute one parameterized statement."""
        try:
            return self.connection.execute(sql, parameters)
        except sqlite3.Error as exc:
            raise StorageError("A storage operation failed.") from exc

    def commit(self) -> None:
        try:
            self.connection.commit()
        except sqlite3.Error as exc:
            raise StorageError("A storage operation could not be saved.") from exc

    def rollback(self) -> None:
        try:
            self.connection.rollback()
        except sqlite3.Error:
            pass

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
