"""Redacted security audit events.

Audit records are useful only if they do not become a second copy of the
secret data. Callers pass short event metadata; this module additionally
truncates details and redacts common credential-bearing patterns as defence
in depth.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from .db import Database

_SECRET_PATTERNS = [
    re.compile(r"(?i)(password\s*[=:]\s*)\S+"),
    re.compile(r"(?i)(token\s*[=:]\s*)\S+"),
    re.compile(r"(?i)(authorization\s*[=:]\s*)\S+"),
    re.compile(r"\b[A-Za-z0-9_-]{43,}\b"),
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


def redact(value: object, limit: int = 160) -> str:
    """Return bounded audit detail with common secret forms removed."""
    text = "" if value is None else str(value)
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            text = pattern.sub(r"\1[REDACTED]", text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text[:limit]


def log_event(
    db: Database,
    *,
    event: str,
    outcome: str,
    user_id: int | None = None,
    detail: object = "",
) -> None:
    """Persist one redacted audit event using a parameterized INSERT."""
    db.execute(
        """
        INSERT INTO audit_events (user_id, event, outcome, detail, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user_id, event[:80], outcome[:40], redact(detail), iso_now()),
    )
    db.commit()
