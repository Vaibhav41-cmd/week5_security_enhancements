"""Central input-validation rules for SecureNotes.

Validation is whitelist-based: a value is accepted only when it has the
expected type, length and character set. This is a usability and integrity
control; database safety does *not* depend on it because all SQL statements
also use bound parameters.
"""

from __future__ import annotations

import re
from pathlib import Path

from .errors import ValidationError

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

MAX_TITLE_LENGTH = 120
MAX_BODY_LENGTH = 10_000
MAX_TAGS = 10
MAX_IMPORT_BYTES = 1_000_000
MAX_IMPORT_NOTES = 100


def validate_username(username: object) -> str:
    """Normalize and validate a username."""
    if not isinstance(username, str):
        raise ValidationError("Username must be text.")
    normalized = username.strip().lower()
    if not USERNAME_RE.fullmatch(normalized):
        raise ValidationError(
            "Username must be 3-32 characters using letters, digits, dot, underscore or hyphen."
        )
    return normalized


def validate_password(password: object) -> str:
    """Enforce a minimum password policy without logging the value."""
    if not isinstance(password, str):
        raise ValidationError("Password must be text.")
    if not 12 <= len(password) <= 128:
        raise ValidationError("Password must be between 12 and 128 characters.")
    classes = sum(
        bool(re.search(pattern, password))
        for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]")
    )
    if classes < 3:
        raise ValidationError(
            "Password must use at least three character types: lower, upper, digit or symbol."
        )
    if password.strip() != password:
        raise ValidationError("Password must not start or end with whitespace.")
    return password


def validate_title(title: object) -> str:
    if not isinstance(title, str):
        raise ValidationError("Title must be text.")
    cleaned = title.strip()
    if not cleaned or len(cleaned) > MAX_TITLE_LENGTH:
        raise ValidationError(f"Title must be between 1 and {MAX_TITLE_LENGTH} characters.")
    if any(ord(char) < 32 and char not in "\t" for char in cleaned):
        raise ValidationError("Title contains unsupported control characters.")
    return cleaned


def validate_body(body: object) -> str:
    if not isinstance(body, str):
        raise ValidationError("Body must be text.")
    if len(body) > MAX_BODY_LENGTH:
        raise ValidationError(f"Body must not exceed {MAX_BODY_LENGTH} characters.")
    # Reject terminal escape/control sequences (except ordinary whitespace)
    # so imported text cannot manipulate the user's terminal when displayed.
    if any(
        (ord(char) < 32 and char not in "\n\r\t") or ord(char) == 127
        for char in body
    ):
        raise ValidationError("Body contains unsupported control characters.")
    return body


def validate_tags(tags: object) -> list[str]:
    """Normalize a tag iterable or comma-separated string."""
    if tags is None:
        raw: list[object] = []
    elif isinstance(tags, str):
        raw = list(tags.split(","))
    elif isinstance(tags, (list, tuple, set)):
        raw = list(tags)
    else:
        raise ValidationError("Tags must be a list or comma-separated text.")

    output: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise ValidationError("Every tag must be text.")
        tag = item.strip().lower()
        if not tag:
            continue
        if not TAG_RE.fullmatch(tag):
            raise ValidationError("Tags may contain only letters, digits, hyphen and underscore.")
        if tag not in output:
            output.append(tag)
    if len(output) > MAX_TAGS:
        raise ValidationError(f"At most {MAX_TAGS} tags are allowed.")
    return output


def validate_search_query(query: object) -> str:
    if not isinstance(query, str):
        raise ValidationError("Search query must be text.")
    cleaned = query.strip()
    if len(cleaned) > 100:
        raise ValidationError("Search query must not exceed 100 characters.")
    return cleaned


def safe_join(base_dir: str | Path, filename: object, *, suffix: str | None = None) -> Path:
    """Join a user filename to a directory, preventing path traversal.

    The basename must match a strict whitelist and the fully resolved final
    path is checked again against the resolved base. The second check is
    defence in depth against platform-specific path surprises.
    """
    if not isinstance(filename, str) or not filename.strip():
        raise ValidationError("Filename is required.")
    name = filename.strip()
    if name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise ValidationError("Filename must not contain a path.")
    if not SAFE_FILENAME_RE.fullmatch(name):
        raise ValidationError("Filename contains unsupported characters.")
    if suffix and Path(name).suffix.lower() != suffix.lower():
        raise ValidationError(f"Filename must end with {suffix}.")

    base = Path(base_dir).expanduser().resolve()
    target = (base / name).resolve()
    if target.parent != base:
        raise ValidationError("Filename would leave the permitted directory.")
    return target
