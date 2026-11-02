"""Owner authorization, validation, file and note-security tests."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from securenotes.auth import AuthContext
from securenotes.db import Database
from securenotes.errors import ConflictError, NotFoundError, ValidationError
from securenotes.service import NoteService


@pytest.mark.functionality
def test_note_crud_and_literal_search(notes: NoteService, alice: AuthContext) -> None:
    created = notes.create_note(alice, "Shopping", "Buy oat milk", ["home"])
    assert notes.get_note(alice, created.id).body == "Buy oat milk"
    assert [note.id for note in notes.search_notes(alice, "oat")] == [created.id]

    updated = notes.update_note(alice, created.id, title="Groceries", tags=["food"])
    assert updated.title == "Groceries"
    assert updated.tags == ["food"]

    notes.delete_note(alice, created.id)
    with pytest.raises(NotFoundError):
        notes.get_note(alice, created.id)


@pytest.mark.security
def test_other_user_cannot_read_update_or_delete_note(
    notes: NoteService, alice: AuthContext, bob: AuthContext
) -> None:
    note = notes.create_note(alice, "Alice secret", "for Alice only")

    with pytest.raises(NotFoundError):
        notes.get_note(bob, note.id)
    with pytest.raises(NotFoundError):
        notes.update_note(bob, note.id, title="Hijacked")
    with pytest.raises(NotFoundError):
        notes.delete_note(bob, note.id)

    assert notes.get_note(alice, note.id).title == "Alice secret"


@pytest.mark.security
@pytest.mark.parametrize(
    "payload",
    ["' ) OR 1=1 --", "%", "_", "'; DROP TABLE notes; --"],
)
def test_search_payloads_are_treated_literally(
    notes: NoteService, alice: AuthContext, payload: str
) -> None:
    notes.create_note(alice, "Ordinary", "ordinary body")
    assert notes.search_notes(alice, payload) == []
    assert len(notes.list_notes(alice)) == 1


@pytest.mark.security
def test_database_contains_no_plaintext_note_or_password(
    db: Database, notes: NoteService, alice: AuthContext
) -> None:
    notes.create_note(alice, "VerySecretTitle", "VerySecretBody", ["secret"])
    db.connection.commit()

    files = [db.path, Path(f"{db.path}-wal"), Path(f"{db.path}-shm")]
    raw = b"".join(path.read_bytes() for path in files if path.exists())
    assert b"VerySecretTitle" not in raw
    assert b"VerySecretBody" not in raw
    assert b"CorrectHorse42" not in raw


@pytest.mark.security
@pytest.mark.parametrize(
    "title,body,tags",
    [
        ("", "body", []),
        ("x" * 121, "body", []),
        ("Title", "x" * 10_001, []),
        ("Title", "\x1b[31mterminal escape", []),
        ("Title", "body", ["bad tag!"]),
        ("Title", "body", [f"tag{i}" for i in range(11)]),
    ],
    ids=[
        "empty-title",
        "title-too-long",
        "body-too-long",
        "terminal-escape",
        "bad-tag",
        "too-many-tags",
    ],
)
def test_note_input_limits(
    notes: NoteService, alice: AuthContext, title: str, body: str, tags: list[str]
) -> None:
    with pytest.raises(ValidationError):
        notes.create_note(alice, title, body, tags)


@pytest.mark.security
@pytest.mark.parametrize("filename", ["../escape.json", "..\\escape.json", "/tmp/escape.json", "bad:name.json"])
def test_export_rejects_path_traversal(
    notes: NoteService, alice: AuthContext, filename: str, tmp_path: Path
) -> None:
    notes.create_note(alice, "Export me", "content")
    with pytest.raises(ValidationError):
        notes.export_notes(alice, filename)
    assert not (tmp_path / "escape.json").exists()


@pytest.mark.functionality
def test_export_contains_only_own_notes(
    notes: NoteService, alice: AuthContext, bob: AuthContext
) -> None:
    notes.create_note(alice, "Alice export", "Alice content")
    notes.create_note(bob, "Bob export", "Bob content")

    path = notes.export_notes(alice, "alice.json")
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert [item["title"] for item in payload["notes"]] == ["Alice export"]
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.functionality
def test_import_valid_json(notes: NoteService, alice: AuthContext, tmp_path: Path) -> None:
    source = tmp_path / "import.json"
    source.write_text(
        json.dumps({"notes": [{"title": "Imported", "body": "Safe", "tags": ["one"]}]}),
        encoding="utf-8",
    )

    assert notes.import_notes(alice, source) == 1
    assert notes.list_notes(alice)[0].title == "Imported"


@pytest.mark.security
@pytest.mark.parametrize(
    "payload",
    [
        {"notes": [{"title": "Bad", "body": "x", "admin": True}]},
        {"notes": [{"title": 123, "body": "x"}]},
        {"notes": "not-a-list"},
    ],
)
def test_import_rejects_invalid_schema(
    notes: NoteService, alice: AuthContext, tmp_path: Path, payload: dict
) -> None:
    source = tmp_path / "bad.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValidationError):
        notes.import_notes(alice, source)


@pytest.mark.security
def test_import_rejects_pickle_and_oversized_files(
    notes: NoteService, alice: AuthContext, tmp_path: Path
) -> None:
    pickle_file = tmp_path / "payload.pkl"
    pickle_file.write_bytes(b"not json")
    with pytest.raises(ValidationError):
        notes.import_notes(alice, pickle_file)

    large = tmp_path / "large.json"
    large.write_bytes(b" " * 1_000_001)
    with pytest.raises(ValidationError):
        notes.import_notes(alice, large)


@pytest.mark.security
def test_backup_uses_safe_name_and_rejects_shell_syntax(
    notes: NoteService, alice: AuthContext, tmp_path: Path
) -> None:
    marker = tmp_path / "command_marker"
    with pytest.raises(ValidationError):
        notes.backup_database(alice, f"backup.db; touch {marker}")
    assert not marker.exists()

    backup = notes.backup_database(alice, "safe-backup.db")
    assert backup.exists()
    if os.name == "posix":
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600

    with pytest.raises(ConflictError):
        notes.backup_database(alice, "safe-backup.db")


@pytest.mark.security
def test_database_file_is_owner_only_on_posix(db: Database) -> None:
    if os.name == "posix":
        assert stat.S_IMODE(db.path.stat().st_mode) == 0o600


@pytest.mark.security
def test_database_does_not_change_existing_parent_permissions(tmp_path: Path) -> None:
    if os.name != "posix":
        pytest.skip("POSIX permission assertion")
    parent = tmp_path / "existing"
    parent.mkdir()
    os.chmod(parent, 0o755)

    database = Database(parent / "notes.db")
    try:
        assert stat.S_IMODE(parent.stat().st_mode) == 0o755
        assert stat.S_IMODE(database.path.stat().st_mode) == 0o600
    finally:
        database.close()
