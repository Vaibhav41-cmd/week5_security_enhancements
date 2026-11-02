"""Shared fixtures for SecureNotes functionality and security tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from securenotes.auth import AuthContext, AuthService
from securenotes.db import Database
from securenotes.service import NoteService

PROJECT_ROOT = Path(__file__).resolve().parents[1]
VULNERABLE_DIR = PROJECT_ROOT / "vulnerable"
if str(VULNERABLE_DIR) not in sys.path:
    sys.path.insert(0, str(VULNERABLE_DIR))

ALICE_PASSWORD = "CorrectHorse42!"  # noqa: S105 - test-only credential
BOB_PASSWORD = "BatteryStaple99!"  # noqa: S105 - test-only credential


@pytest.fixture
def db(tmp_path: Path):
    database = Database(tmp_path / "secure.db")
    yield database
    database.close()


@pytest.fixture
def auth(db: Database) -> AuthService:
    return AuthService(db)


@pytest.fixture
def notes(db: Database, tmp_path: Path) -> NoteService:
    return NoteService(db, tmp_path / "exports")


@pytest.fixture
def alice(auth: AuthService) -> AuthContext:
    return auth.register("Alice", ALICE_PASSWORD)


@pytest.fixture
def bob(auth: AuthService) -> AuthContext:
    return auth.register("bob", BOB_PASSWORD)
