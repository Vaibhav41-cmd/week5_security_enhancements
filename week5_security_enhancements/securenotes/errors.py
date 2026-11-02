"""Application errors with intentionally safe user-facing messages.

Internal exception details (SQL text, file paths, cryptographic failures and
tracebacks) are not copied into these messages. The CLI can therefore print an
``AppError`` directly without leaking implementation details.
"""


class AppError(Exception):
    """Base class for expected, safely reportable application failures."""


class ValidationError(AppError):
    """Input failed a documented validation rule."""


class AuthenticationError(AppError):
    """Authentication failed; callers should use a generic message."""


class AccountLockedError(AuthenticationError):
    """Authentication is temporarily blocked by the lockout policy."""


class AuthorizationError(AppError):
    """The authenticated user is not allowed to perform an operation."""


class NotFoundError(AppError):
    """A resource does not exist or is not visible to this user."""


class ConflictError(AppError):
    """A create operation conflicts with existing state."""


class StorageError(AppError):
    """A storage operation failed without exposing internal details."""
