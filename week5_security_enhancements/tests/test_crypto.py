"""Cryptographic control tests."""

from __future__ import annotations

import pytest

from securenotes.crypto import (
    PBKDF2_ITERATIONS,
    decrypt_text,
    derive_fernet,
    encrypt_text,
    hash_password,
    new_key_salt,
    new_session_token,
    token_digest,
    verify_password,
)
from securenotes.errors import AuthenticationError


@pytest.mark.security
def test_password_hash_is_salted_pbkdf2_and_verifiable() -> None:
    first = hash_password("CorrectHorse42!")
    second = hash_password("CorrectHorse42!")

    assert first.startswith(f"pbkdf2_sha256${PBKDF2_ITERATIONS}$")
    assert PBKDF2_ITERATIONS >= 600_000
    assert first != second  # independent random salts
    assert verify_password("CorrectHorse42!", first)
    assert not verify_password("WrongHorse42!", first)


@pytest.mark.security
def test_password_hash_tampering_fails() -> None:
    stored = hash_password("CorrectHorse42!")
    tampered = stored[:-1] + ("A" if stored[-1] != "A" else "B")
    assert not verify_password("CorrectHorse42!", tampered)


@pytest.mark.security
def test_note_encryption_requires_correct_password_derived_key() -> None:
    salt = new_key_salt()
    correct = derive_fernet("CorrectHorse42!", salt)
    wrong = derive_fernet("WrongHorse42!", salt)
    ciphertext = encrypt_text(correct, "launch plan")

    assert "launch plan" not in ciphertext
    assert decrypt_text(correct, ciphertext) == "launch plan"
    with pytest.raises(AuthenticationError):
        decrypt_text(wrong, ciphertext)


@pytest.mark.security
def test_session_token_is_long_random_and_only_digest_is_stored() -> None:
    token_one = new_session_token()
    token_two = new_session_token()

    assert len(token_one) >= 43
    assert token_one != token_two
    assert token_digest(token_one) != token_one
    assert len(token_digest(token_one)) == 64
