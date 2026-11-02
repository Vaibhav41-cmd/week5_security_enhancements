"""Password hashing and authenticated note encryption.

Controls implemented here:

* Passwords are hashed with PBKDF2-HMAC-SHA256, a per-user random salt and
  600,000 iterations. The parameters are stored with the hash so they can be
  raised later.
* Verification uses :func:`hmac.compare_digest`.
* Note fields are encrypted with Fernet (AES-128-CBC with HMAC in the
  ``cryptography`` implementation) using a key derived from the user's
  password and a separate random salt.
* Session tokens are generated with ``secrets`` and only their SHA-256 digest
  is suitable for database storage.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .errors import AuthenticationError, StorageError

# Public algorithm identifier, not a credential; targeted Bandit triage.
PASSWORD_ALGORITHM = "pbkdf2_sha256"  # nosec B105
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
TOKEN_BYTES = 32


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def hash_password(password: str) -> str:
    """Return a self-describing salted PBKDF2 password record."""
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return "$".join(
        [PASSWORD_ALGORITHM, str(PBKDF2_ITERATIONS), _b64encode(salt), _b64encode(digest)]
    )


def verify_password(password: str, stored: str) -> bool:
    """Verify a password in constant time with respect to the digest bytes."""
    try:
        algorithm, iterations_text, salt_text, digest_text = stored.split("$", 3)
        if algorithm != PASSWORD_ALGORITHM:
            return False
        iterations = int(iterations_text)
        salt = _b64decode(salt_text)
        expected = _b64decode(digest_text)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(candidate, expected)


# A real PBKDF2 record for a random throwaway value. Login for an unknown
# username runs the same verification work against this record so timing and
# messages do not provide a simple account-enumeration oracle.
DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


def new_key_salt() -> str:
    """Return a fresh encryption-key salt for database storage."""
    return _b64encode(secrets.token_bytes(SALT_BYTES))


def derive_fernet(password: str, key_salt: str) -> Fernet:
    """Derive the user's note-encryption key from the correct password."""
    try:
        salt = _b64decode(key_salt)
    except (ValueError, TypeError) as exc:
        raise StorageError("Stored encryption metadata is invalid.") from exc
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    return Fernet(key)


def encrypt_text(fernet: Fernet, plaintext: str) -> str:
    """Encrypt UTF-8 text and return an ASCII Fernet token."""
    return fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_text(fernet: Fernet, ciphertext: str) -> str:
    """Decrypt a Fernet token without exposing cryptographic details."""
    try:
        return fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError) as exc:
        raise AuthenticationError("Note data cannot be decrypted for this account.") from exc


def new_session_token() -> str:
    """Create an unpredictable bearer token for one session."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_digest(token: str) -> str:
    """Return the database representation of a session token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
