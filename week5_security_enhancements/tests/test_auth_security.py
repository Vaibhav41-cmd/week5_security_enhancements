"""Authentication, session and account-security tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from securenotes.audit import iso_now, utc_now
from securenotes.auth import AuthContext, AuthService
from securenotes.crypto import token_digest
from securenotes.db import Database
from securenotes.errors import (
    AccountLockedError,
    AuthenticationError,
    ConflictError,
    ValidationError,
)
from securenotes.service import NoteService
from tests.conftest import ALICE_PASSWORD


@pytest.mark.functionality
def test_register_normalizes_username(auth: AuthService, alice: AuthContext) -> None:
    assert alice.username == "alice"
    authenticated = auth.authenticate("ALICE", ALICE_PASSWORD)
    assert authenticated.user_id == alice.user_id


@pytest.mark.security
def test_duplicate_username_is_rejected(auth: AuthService, alice: AuthContext) -> None:
    with pytest.raises(ConflictError):
        auth.register("alice", "AnotherStrong42!")


@pytest.mark.security
@pytest.mark.parametrize(
    "password",
    ["short", "alllowercaseletters", "123456789012", " CorrectHorse42!"],
)
def test_weak_passwords_are_rejected(auth: AuthService, password: str) -> None:
    with pytest.raises(ValidationError):
        auth.register("weakuser", password)


@pytest.mark.security
def test_unknown_user_and_wrong_password_have_same_message(
    auth: AuthService, alice: AuthContext
) -> None:
    with pytest.raises(AuthenticationError) as unknown:
        auth.authenticate("nosuchuser", ALICE_PASSWORD)
    with pytest.raises(AuthenticationError) as wrong:
        auth.authenticate("alice", "WrongHorse42!")

    assert str(unknown.value) == str(wrong.value) == "Invalid username or password."


@pytest.mark.security
@pytest.mark.parametrize(
    "username,password",
    [
        ("alice' --", "anything"),
        ("' OR '1'='1' --", "anything"),
        ("alice", "' OR '1'='1"),
    ],
)
def test_sql_injection_login_payloads_fail(
    auth: AuthService, alice: AuthContext, username: str, password: str
) -> None:
    with pytest.raises(AuthenticationError):
        auth.authenticate(username, password)


@pytest.mark.security
def test_account_locks_after_five_failed_attempts(
    auth: AuthService, alice: AuthContext
) -> None:
    for _ in range(5):
        with pytest.raises(AuthenticationError):
            auth.authenticate("alice", "WrongHorse42!")

    with pytest.raises(AccountLockedError):
        auth.authenticate("alice", ALICE_PASSWORD)


@pytest.mark.security
def test_expired_lock_can_be_cleared(
    db: Database, auth: AuthService, alice: AuthContext
) -> None:
    past = (utc_now() - timedelta(minutes=1)).isoformat(timespec="seconds")
    db.execute(
        "UPDATE users SET failed_attempts = 5, locked_until = ? WHERE id = ?",
        (past, alice.user_id),
    )
    db.commit()

    assert auth.authenticate("alice", ALICE_PASSWORD).user_id == alice.user_id


@pytest.mark.security
def test_session_is_hashed_validated_and_revoked(
    db: Database, auth: AuthService, alice: AuthContext
) -> None:
    row = db.execute(
        "SELECT token_hash FROM sessions WHERE user_id = ?", (alice.user_id,)
    ).fetchone()
    assert row["token_hash"] == token_digest(alice.session_token)
    assert row["token_hash"] != alice.session_token

    info = auth.validate_session(alice.session_token)
    assert info.username == "alice"

    auth.logout(alice.session_token)
    with pytest.raises(AuthenticationError):
        auth.validate_session(alice.session_token)


@pytest.mark.security
def test_expired_session_is_rejected(
    db: Database, auth: AuthService, alice: AuthContext
) -> None:
    past = (utc_now() - timedelta(seconds=1)).isoformat(timespec="seconds")
    db.execute(
        "UPDATE sessions SET expires_at = ? WHERE user_id = ?",
        (past, alice.user_id),
    )
    db.commit()

    with pytest.raises(AuthenticationError):
        auth.validate_session(alice.session_token)


@pytest.mark.security
@pytest.mark.functionality
def test_password_change_reencrypts_notes_and_revokes_old_session(
    auth: AuthService, notes: NoteService, alice: AuthContext
) -> None:
    note = notes.create_note(alice, "Secret", "rotate this secret", ["private"])
    old_token = alice.session_token

    changed = auth.change_password(alice, ALICE_PASSWORD, "NewBattery42!")

    with pytest.raises(AuthenticationError):
        auth.validate_session(old_token)
    with pytest.raises(AuthenticationError):
        auth.authenticate("alice", ALICE_PASSWORD)

    new_context = auth.authenticate("alice", "NewBattery42!")
    assert notes.get_note(new_context, note.id).body == "rotate this secret"
    assert changed.session_token != old_token


@pytest.mark.security
def test_audit_log_redacts_passwords_and_tokens(
    db: Database, auth: AuthService, alice: AuthContext
) -> None:
    auth.authenticate("alice", ALICE_PASSWORD)
    rows = db.execute("SELECT event, outcome, detail FROM audit_events").fetchall()
    rendered = repr([dict(row) for row in rows])

    assert ALICE_PASSWORD not in rendered
    assert alice.session_token not in rendered
    assert rows


@pytest.mark.security
def test_session_expiry_uses_utc_timestamp(alice: AuthContext) -> None:
    assert alice.session_expires_at.endswith("+00:00")
    assert iso_now().endswith("+00:00")
