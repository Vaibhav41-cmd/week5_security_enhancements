"""Quarantined baseline attack simulations.

These tests intentionally assert that dangerous payloads *succeed* against
``vulnerable/vulnerable_app.py``. They create only temporary marker files and
databases. The secure counterparts are asserted in the other test modules.
"""

from __future__ import annotations

import hashlib
import os
import pickle
import re
import sqlite3
import time
from pathlib import Path

import pytest

from vulnerable_app import VulnerableNotesApp


@pytest.fixture
def vulnerable(tmp_path: Path):
    app = VulnerableNotesApp(tmp_path / "vulnerable.db", tmp_path / "exports")
    user_id = app.register("alice", "password")
    note_id = app.create_note(user_id, "Alice secret", "BASELINE-SECRET")
    yield app, user_id, note_id
    app.close()


class PickleCanary:
    """Harmless local canary proving pickle can invoke OS functionality."""

    def __init__(self, marker: Path) -> None:
        self.marker = marker

    def __reduce__(self):
        return (os.system, (f"touch {self.marker}",))


@pytest.mark.attack
def test_baseline_sql_injection_bypasses_login(vulnerable) -> None:
    app, user_id, _ = vulnerable
    token = app.login("alice' --", "wrong")
    assert re.fullmatch(rf"session-{user_id}-\d+", token)


@pytest.mark.attack
def test_baseline_search_injection_crosses_user_boundary(vulnerable) -> None:
    app, _, _ = vulnerable
    results = app.search_notes(999, "' ) OR 1=1 --")
    assert results[0]["body"] == "BASELINE-SECRET"


@pytest.mark.attack
def test_baseline_idor_and_plaintext_storage(vulnerable, tmp_path: Path) -> None:
    app, _, note_id = vulnerable
    assert app.get_note(note_id)["body"] == "BASELINE-SECRET"

    raw = (tmp_path / "vulnerable.db").read_bytes()
    assert b"BASELINE-SECRET" in raw


@pytest.mark.attack
def test_baseline_password_is_unsalted_md5(vulnerable, tmp_path: Path) -> None:
    connection = sqlite3.connect(tmp_path / "vulnerable.db")
    try:
        stored = connection.execute(
            "SELECT password_md5 FROM users WHERE username = 'alice'"
        ).fetchone()[0]
    finally:
        connection.close()

    assert stored == hashlib.md5(b"password").hexdigest()  # noqa: S324


@pytest.mark.attack
def test_baseline_session_is_predictable_and_raw(vulnerable) -> None:
    app, user_id, _ = vulnerable
    before = int(time.time())
    token = app.login("alice", "password")
    after = int(time.time())

    match = re.fullmatch(rf"session-{user_id}-(\d+)", token)
    assert match is not None
    assert before <= int(match.group(1)) <= after
    stored = app.connection.execute(
        "SELECT session_token FROM users WHERE id = ?", (user_id,)
    ).fetchone()[0]
    assert stored == token  # raw, directly reusable database value


@pytest.mark.attack
def test_baseline_logs_password_and_note_body(vulnerable) -> None:
    app, _, _ = vulnerable
    assert any("password" in line for line in app.logs)
    assert any("BASELINE-SECRET" in line for line in app.logs)


@pytest.mark.attack
def test_baseline_path_traversal(vulnerable, tmp_path: Path) -> None:
    app, user_id, _ = vulnerable
    written = app.export_all_notes("../escaped.txt")
    assert written.resolve() == tmp_path / "escaped.txt"
    assert "BASELINE-SECRET" in written.read_text(encoding="utf-8")


@pytest.mark.attack
def test_baseline_command_injection(vulnerable, tmp_path: Path) -> None:
    app, _, _ = vulnerable
    marker = tmp_path / "command_marker"
    app.backup_database(f"backup.db; touch {marker}")
    assert marker.exists()


@pytest.mark.attack
def test_baseline_pickle_deserialization_executes_canary(
    vulnerable, tmp_path: Path
) -> None:
    app, user_id, _ = vulnerable
    marker = tmp_path / "pickle_marker"
    payload = tmp_path / "canary.pkl"
    payload.write_bytes(pickle.dumps(PickleCanary(marker)))

    app.import_pickle(payload)
    assert marker.exists()
