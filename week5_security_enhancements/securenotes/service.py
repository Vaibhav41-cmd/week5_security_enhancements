"""Encrypted, owner-scoped note operations."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .audit import iso_now, log_event
from .auth import AuthContext
from .crypto import decrypt_text, encrypt_text
from .db import Database
from .errors import ConflictError, NotFoundError, StorageError, ValidationError
from .validation import (
    MAX_IMPORT_BYTES,
    MAX_IMPORT_NOTES,
    safe_join,
    validate_body,
    validate_search_query,
    validate_tags,
    validate_title,
)

NOTE_NOT_FOUND = "Note not found."


@dataclass(frozen=True)
class Note:
    id: int
    title: str
    body: str
    tags: list[str]
    created_at: str
    updated_at: str


class NoteService:
    """All note methods require an authenticated password-derived context."""

    def __init__(self, db: Database, export_dir: str | Path = "data/exports") -> None:
        self.db = db
        self.export_dir = Path(export_dir)

    @staticmethod
    def _clean_note_id(note_id: object) -> int:
        if isinstance(note_id, bool) or not isinstance(note_id, int) or note_id <= 0:
            raise NotFoundError(NOTE_NOT_FOUND)
        return note_id

    @staticmethod
    def _decrypt_row(context: AuthContext, row) -> Note:
        tags_text = decrypt_text(context.fernet, str(row["tags_ciphertext"]))
        try:
            tags = json.loads(tags_text)
        except json.JSONDecodeError as exc:
            raise StorageError("Stored note metadata is invalid.") from exc
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            raise StorageError("Stored note metadata is invalid.")
        return Note(
            id=int(row["id"]),
            title=decrypt_text(context.fernet, str(row["title_ciphertext"])),
            body=decrypt_text(context.fernet, str(row["body_ciphertext"])),
            tags=tags,
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    def create_note(
        self,
        context: AuthContext,
        title: object,
        body: object,
        tags: object = None,
    ) -> Note:
        clean_title = validate_title(title)
        clean_body = validate_body(body)
        clean_tags = validate_tags(tags)
        now = iso_now()
        cursor = self.db.execute(
            """
            INSERT INTO notes
                (user_id, title_ciphertext, body_ciphertext, tags_ciphertext, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                context.user_id,
                encrypt_text(context.fernet, clean_title),
                encrypt_text(context.fernet, clean_body),
                encrypt_text(context.fernet, json.dumps(clean_tags)),
                now,
                now,
            ),
        )
        self.db.commit()
        note = Note(
            id=int(cursor.lastrowid),
            title=clean_title,
            body=clean_body,
            tags=clean_tags,
            created_at=now,
            updated_at=now,
        )
        log_event(
            self.db,
            event="note_create",
            outcome="success",
            user_id=context.user_id,
            detail=f"note_id={note.id}",
        )
        return note

    def get_note(self, context: AuthContext, note_id: object) -> Note:
        clean_id = self._clean_note_id(note_id)
        row = self.db.execute(
            """
            SELECT id, title_ciphertext, body_ciphertext, tags_ciphertext, created_at, updated_at
            FROM notes WHERE id = ? AND user_id = ?
            """,
            (clean_id, context.user_id),
        ).fetchone()
        if row is None:
            log_event(
                self.db,
                event="note_read",
                outcome="not_found",
                user_id=context.user_id,
                detail=f"note_id={clean_id}",
            )
            raise NotFoundError(NOTE_NOT_FOUND)
        return self._decrypt_row(context, row)

    def list_notes(self, context: AuthContext) -> list[Note]:
        rows = self.db.execute(
            """
            SELECT id, title_ciphertext, body_ciphertext, tags_ciphertext, created_at, updated_at
            FROM notes WHERE user_id = ? ORDER BY id
            """,
            (context.user_id,),
        ).fetchall()
        return [self._decrypt_row(context, row) for row in rows]

    def search_notes(self, context: AuthContext, query: object) -> list[Note]:
        """Literal owner-scoped search; query text is never placed into SQL."""
        clean_query = validate_search_query(query).casefold()
        notes = self.list_notes(context)
        if not clean_query:
            return notes
        return [
            note
            for note in notes
            if clean_query in note.title.casefold()
            or clean_query in note.body.casefold()
            or any(clean_query in tag.casefold() for tag in note.tags)
        ]

    def update_note(
        self,
        context: AuthContext,
        note_id: object,
        *,
        title: object = None,
        body: object = None,
        tags: object = None,
    ) -> Note:
        existing = self.get_note(context, note_id)
        updated = Note(
            id=existing.id,
            title=existing.title if title is None else validate_title(title),
            body=existing.body if body is None else validate_body(body),
            tags=existing.tags if tags is None else validate_tags(tags),
            created_at=existing.created_at,
            updated_at=iso_now(),
        )
        cursor = self.db.execute(
            """
            UPDATE notes
            SET title_ciphertext = ?, body_ciphertext = ?, tags_ciphertext = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                encrypt_text(context.fernet, updated.title),
                encrypt_text(context.fernet, updated.body),
                encrypt_text(context.fernet, json.dumps(updated.tags)),
                updated.updated_at,
                updated.id,
                context.user_id,
            ),
        )
        if cursor.rowcount != 1:
            self.db.rollback()
            raise NotFoundError(NOTE_NOT_FOUND)
        self.db.commit()
        log_event(
            self.db,
            event="note_update",
            outcome="success",
            user_id=context.user_id,
            detail=f"note_id={updated.id}",
        )
        return updated

    def delete_note(self, context: AuthContext, note_id: object) -> None:
        clean_id = self._clean_note_id(note_id)
        cursor = self.db.execute(
            "DELETE FROM notes WHERE id = ? AND user_id = ?",
            (clean_id, context.user_id),
        )
        if cursor.rowcount != 1:
            self.db.rollback()
            log_event(
                self.db,
                event="note_delete",
                outcome="not_found",
                user_id=context.user_id,
                detail=f"note_id={clean_id}",
            )
            raise NotFoundError(NOTE_NOT_FOUND)
        self.db.commit()
        log_event(
            self.db,
            event="note_delete",
            outcome="success",
            user_id=context.user_id,
            detail=f"note_id={clean_id}",
        )

    def export_notes(self, context: AuthContext, filename: object) -> Path:
        """Export only this user's decrypted notes inside the export directory."""
        target = safe_join(self.export_dir, filename, suffix=".json")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(target.parent, 0o700)
        except OSError:
            pass

        payload = {
            "format": "securenotes-export-v1",
            "notes": [
                {"title": note.title, "body": note.body, "tags": note.tags}
                for note in self.list_notes(context)
            ],
        }
        temporary = target.with_suffix(".tmp")
        # Create and tighten the descriptor before decrypted JSON is written;
        # chmod-after-write would leave a brief default-permission window.
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
        )
        try:
            os.fchmod(descriptor, 0o600)
        except (AttributeError, OSError):
            pass
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        os.replace(temporary, target)
        log_event(
            self.db,
            event="notes_export",
            outcome="success",
            user_id=context.user_id,
            detail=f"count={len(payload['notes'])}",
        )
        return target

    def import_notes(self, context: AuthContext, source: str | Path) -> int:
        """Import schema-validated JSON only; pickle is never accepted."""
        path = Path(source).expanduser()
        if path.suffix.lower() != ".json" or not path.is_file():
            raise ValidationError("Import source must be an existing JSON file.")
        with path.open("rb") as handle:
            raw = handle.read(MAX_IMPORT_BYTES + 1)
        if len(raw) > MAX_IMPORT_BYTES:
            raise ValidationError("Import file is too large.")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("Import file is not valid JSON.") from exc

        items = payload.get("notes") if isinstance(payload, dict) else payload
        if not isinstance(items, list) or len(items) > MAX_IMPORT_NOTES:
            raise ValidationError("Import file must contain a bounded list of notes.")

        cleaned: list[tuple[str, str, list[str]]] = []
        for item in items:
            if not isinstance(item, dict) or set(item) - {"title", "body", "tags"}:
                raise ValidationError("Each imported note has an unsupported structure.")
            cleaned.append(
                (
                    validate_title(item.get("title")),
                    validate_body(item.get("body", "")),
                    validate_tags(item.get("tags", [])),
                )
            )

        now = iso_now()
        try:
            for title, body, tags in cleaned:
                self.db.execute(
                    """
                    INSERT INTO notes
                        (user_id, title_ciphertext, body_ciphertext, tags_ciphertext, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        context.user_id,
                        encrypt_text(context.fernet, title),
                        encrypt_text(context.fernet, body),
                        encrypt_text(context.fernet, json.dumps(tags)),
                        now,
                        now,
                    ),
                )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

        log_event(
            self.db,
            event="notes_import",
            outcome="success",
            user_id=context.user_id,
            detail=f"count={len(cleaned)}",
        )
        return len(cleaned)

    def backup_database(self, context: AuthContext, filename: object) -> Path:
        """Create a SQLite backup with the backup API; no shell is invoked."""
        backup_dir = self.export_dir / "backups"
        target = safe_join(backup_dir, filename, suffix=".db")
        if target.resolve() == self.db.path.resolve():
            raise ValidationError("Backup destination must differ from the live database.")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            # O_EXCL makes the existence check atomic, and the file is born
            # owner-only rather than being tightened after SQLite fills it.
            descriptor = os.open(
                target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
        except FileExistsError as exc:
            raise ConflictError("A backup with that filename already exists.") from exc
        os.close(descriptor)

        destination = sqlite3.connect(target)
        try:
            self.db.connection.backup(destination)
        except sqlite3.Error as exc:
            target.unlink(missing_ok=True)
            raise StorageError("A storage operation failed.") from exc
        finally:
            destination.close()
        try:
            os.chmod(target.parent, 0o700)
            os.chmod(target, 0o600)
        except OSError:
            pass
        log_event(
            self.db,
            event="database_backup",
            outcome="success",
            user_id=context.user_id,
        )
        return target
