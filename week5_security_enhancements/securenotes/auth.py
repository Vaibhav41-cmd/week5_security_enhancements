"""Registration, authentication, sessions and password changes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet

from .audit import iso_now, log_event, utc_now
from .crypto import (
    DUMMY_PASSWORD_HASH,
    decrypt_text,
    derive_fernet,
    encrypt_text,
    hash_password,
    new_key_salt,
    new_session_token,
    token_digest,
    verify_password,
)
from .db import Database
from .errors import (
    AccountLockedError,
    AuthenticationError,
    ConflictError,
    ValidationError,
)
from .validation import validate_password, validate_username

GENERIC_LOGIN_ERROR = "Invalid username or password."


@dataclass(frozen=True)
class AuthContext:
    """In-memory authenticated context.

    ``fernet`` exists only after a correct password is supplied. It is not
    stored in SQLite and is excluded from the representation.
    """

    user_id: int
    username: str
    session_token: str
    session_expires_at: str
    fernet: Fernet = field(repr=False)


@dataclass(frozen=True)
class SessionInfo:
    user_id: int
    username: str
    expires_at: str


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class AuthService:
    def __init__(
        self,
        db: Database,
        *,
        session_ttl_minutes: int = 30,
        max_failed_attempts: int = 5,
        lockout_minutes: int = 15,
    ) -> None:
        self.db = db
        self.session_ttl = timedelta(minutes=session_ttl_minutes)
        self.max_failed_attempts = max_failed_attempts
        self.lockout = timedelta(minutes=lockout_minutes)

    def _create_session(self, user_id: int) -> tuple[str, str]:
        token = new_session_token()
        expires = utc_now() + self.session_ttl
        expires_text = expires.isoformat(timespec="seconds")
        self.db.execute(
            """
            INSERT INTO sessions (user_id, token_hash, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, token_digest(token), iso_now(), expires_text),
        )
        self.db.commit()
        return token, expires_text

    def register(self, username: object, password: object) -> AuthContext:
        """Create an account and return an authenticated context."""
        clean_username = validate_username(username)
        clean_password = validate_password(password)

        existing = self.db.execute(
            "SELECT id FROM users WHERE username = ?", (clean_username,)
        ).fetchone()
        if existing is not None:
            log_event(
                self.db,
                event="register",
                outcome="conflict",
                detail=f"username={clean_username}",
            )
            raise ConflictError("That username is unavailable.")

        key_salt = new_key_salt()
        cursor = self.db.execute(
            """
            INSERT INTO users (username, password_hash, key_salt, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (clean_username, hash_password(clean_password), key_salt, iso_now()),
        )
        self.db.commit()
        user_id = int(cursor.lastrowid)
        token, expires = self._create_session(user_id)
        log_event(self.db, event="register", outcome="success", user_id=user_id)
        return AuthContext(
            user_id=user_id,
            username=clean_username,
            session_token=token,
            session_expires_at=expires,
            fernet=derive_fernet(clean_password, key_salt),
        )

    def authenticate(self, username: object, password: object) -> AuthContext:
        """Authenticate with generic failures and temporary lockout."""
        try:
            clean_username = validate_username(username)
        except ValidationError:
            verify_password(str(password), DUMMY_PASSWORD_HASH)
            raise AuthenticationError(GENERIC_LOGIN_ERROR) from None
        if not isinstance(password, str):
            verify_password("", DUMMY_PASSWORD_HASH)
            raise AuthenticationError(GENERIC_LOGIN_ERROR)

        row = self.db.execute(
            """
            SELECT id, username, password_hash, key_salt, failed_attempts, locked_until
            FROM users WHERE username = ?
            """,
            (clean_username,),
        ).fetchone()

        if row is None:
            # Same message and comparable PBKDF2 work as a real account.
            verify_password(password, DUMMY_PASSWORD_HASH)
            log_event(
                self.db,
                event="login",
                outcome="failure",
                detail=f"username={clean_username}",
            )
            raise AuthenticationError(GENERIC_LOGIN_ERROR)

        user_id = int(row["id"])
        now = utc_now()
        locked_until = _parse_time(row["locked_until"])
        failed_attempts = int(row["failed_attempts"])
        if locked_until is not None and locked_until <= now:
            failed_attempts = 0
            locked_until = None
            self.db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user_id,),
            )
            self.db.commit()

        password_ok = verify_password(password, str(row["password_hash"]))
        if not password_ok:
            if locked_until is None:
                failed_attempts += 1
                new_lock = None
                if failed_attempts >= self.max_failed_attempts:
                    new_lock = (now + self.lockout).isoformat(timespec="seconds")
                self.db.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (failed_attempts, new_lock, user_id),
                )
                self.db.commit()
            log_event(self.db, event="login", outcome="failure", user_id=user_id)
            raise AuthenticationError(GENERIC_LOGIN_ERROR)

        if locked_until is not None and locked_until > now:
            log_event(self.db, event="login", outcome="locked", user_id=user_id)
            raise AccountLockedError("Account is temporarily locked. Please try again later.")

        self.db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,),
        )
        self.db.commit()
        token, expires = self._create_session(user_id)
        log_event(self.db, event="login", outcome="success", user_id=user_id)
        return AuthContext(
            user_id=user_id,
            username=str(row["username"]),
            session_token=token,
            session_expires_at=expires,
            fernet=derive_fernet(password, str(row["key_salt"])),
        )

    def validate_session(self, token: object) -> SessionInfo:
        """Validate a raw bearer token against its stored digest/expiry."""
        if not isinstance(token, str) or not token or len(token) > 200:
            raise AuthenticationError("Session is invalid or expired.")
        row = self.db.execute(
            """
            SELECT sessions.user_id, users.username, sessions.expires_at
            FROM sessions JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ?
            """,
            (token_digest(token),),
        ).fetchone()
        if row is None:
            raise AuthenticationError("Session is invalid or expired.")
        expires = _parse_time(str(row["expires_at"]))
        if expires is None or expires <= utc_now():
            self.db.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),)
            )
            self.db.commit()
            raise AuthenticationError("Session is invalid or expired.")
        return SessionInfo(
            user_id=int(row["user_id"]),
            username=str(row["username"]),
            expires_at=str(row["expires_at"]),
        )

    def logout(self, token: object) -> None:
        """Revoke a session; unknown tokens receive the same quiet result."""
        if isinstance(token, str) and token:
            self.db.execute(
                "DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),)
            )
            self.db.commit()

    def change_password(
        self,
        context: AuthContext,
        current_password: object,
        new_password: object,
    ) -> AuthContext:
        """Change a password and re-encrypt every note under the new key."""
        if not isinstance(current_password, str):
            raise AuthenticationError(GENERIC_LOGIN_ERROR)
        clean_new_password = validate_password(new_password)
        row = self.db.execute(
            "SELECT password_hash, key_salt FROM users WHERE id = ?",
            (context.user_id,),
        ).fetchone()
        if row is None or not verify_password(current_password, str(row["password_hash"])):
            log_event(
                self.db,
                event="password_change",
                outcome="failure",
                user_id=context.user_id,
            )
            raise AuthenticationError(GENERIC_LOGIN_ERROR)

        old_fernet = derive_fernet(current_password, str(row["key_salt"]))
        new_salt = new_key_salt()
        new_fernet = derive_fernet(clean_new_password, new_salt)
        notes = self.db.execute(
            """
            SELECT id, title_ciphertext, body_ciphertext, tags_ciphertext
            FROM notes WHERE user_id = ?
            """,
            (context.user_id,),
        ).fetchall()

        try:
            for note in notes:
                self.db.execute(
                    """
                    UPDATE notes
                    SET title_ciphertext = ?, body_ciphertext = ?, tags_ciphertext = ?
                    WHERE id = ? AND user_id = ?
                    """,
                    (
                        encrypt_text(new_fernet, decrypt_text(old_fernet, str(note["title_ciphertext"]))),
                        encrypt_text(new_fernet, decrypt_text(old_fernet, str(note["body_ciphertext"]))),
                        encrypt_text(new_fernet, decrypt_text(old_fernet, str(note["tags_ciphertext"]))),
                        int(note["id"]),
                        context.user_id,
                    ),
                )
            self.db.execute(
                """
                UPDATE users
                SET password_hash = ?, key_salt = ?, failed_attempts = 0, locked_until = NULL
                WHERE id = ?
                """,
                (hash_password(clean_new_password), new_salt, context.user_id),
            )
            self.db.execute("DELETE FROM sessions WHERE user_id = ?", (context.user_id,))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

        token, expires = self._create_session(context.user_id)
        log_event(
            self.db,
            event="password_change",
            outcome="success",
            user_id=context.user_id,
        )
        return AuthContext(
            user_id=context.user_id,
            username=context.username,
            session_token=token,
            session_expires_at=expires,
            fernet=new_fernet,
        )
