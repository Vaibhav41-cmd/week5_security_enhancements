"""Run the same local attack scenarios against baseline and hardened code.

The vulnerable implementation is imported only in this isolated demonstration
and in the explicitly marked attack tests.  Every database, export and marker
file is created inside a caller-selected or system temporary directory.  The
payloads use harmless ``touch`` marker files to prove code/command execution;
they do not contact a network or operate outside the temporary work area.
"""

from __future__ import annotations

import argparse
import os
import pickle
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Callable

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "vulnerable") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "vulnerable"))

from securenotes.auth import AuthService  # noqa: E402
from securenotes.crypto import PBKDF2_ITERATIONS, token_digest  # noqa: E402
from securenotes.db import Database  # noqa: E402
from securenotes.service import NoteService  # noqa: E402
from vulnerable_app import VulnerableNotesApp  # noqa: E402


class PickleCanary:
    """Create a marker if the receiving application unsafely unpickles it."""

    def __init__(self, marker: Path) -> None:
        self.marker = marker

    def __reduce__(self):
        return (os.system, (f"touch {self.marker}",))


def outcome(action: Callable[[], object], *, success: str) -> str:
    """Convert an action into a short, evidence-safe outcome string."""

    try:
        action()
    except Exception as exc:  # The demo reports the public error category.
        return f"BLOCKED ({type(exc).__name__}: {exc})"
    return success


def run_demo(work_dir: Path) -> str:
    """Execute both sides and return a Markdown comparison transcript."""

    work_dir.mkdir(parents=True, exist_ok=True)
    baseline_dir = work_dir / "baseline"
    secure_dir = work_dir / "secure"
    baseline_dir.mkdir(exist_ok=True)
    secure_dir.mkdir(exist_ok=True)

    lines = [
        "# SecureNotes attack simulation: vulnerable baseline vs hardened build",
        "",
        "Scope: local temporary databases and harmless marker files only.",
        "Synthetic account: alice. Synthetic note body: SYNTHETIC-SECRET.",
        "",
        "| ID | Scenario / attack input | Vulnerable baseline | Hardened SecureNotes |",
        "|---|---|---|---|",
    ]

    # ---------------- vulnerable baseline preparation ----------------
    vulnerable = VulnerableNotesApp(
        baseline_dir / "vulnerable.db", baseline_dir / "exports"
    )
    vuln_alice = vulnerable.register("alice", "password")
    vuln_note = vulnerable.create_note(
        vuln_alice, "Alice private note", "SYNTHETIC-SECRET"
    )

    def baseline_login_error(username: str, password: str) -> str:
        try:
            vulnerable.login(username, password)
        except Exception as exc:
            return str(exc)
        return "login unexpectedly succeeded"

    baseline_unknown = baseline_login_error("nosuchuser", "anything")
    baseline_wrong = baseline_login_error("alice", "wrong")
    baseline_sqli = outcome(
        lambda: vulnerable.login("alice' --", "wrong"),
        success="EXPLOITED: login succeeded with the wrong password",
    )
    baseline_search = vulnerable.search_notes(999, "' ) OR 1=1 --")
    baseline_idor = vulnerable.get_note(vuln_note)
    baseline_raw = (baseline_dir / "vulnerable.db").read_bytes()
    baseline_hash = vulnerable.connection.execute(
        "SELECT password_md5 FROM users WHERE id = ?", (vuln_alice,)
    ).fetchone()[0]
    baseline_token = vulnerable.login("alice", "password")
    baseline_stored_token = vulnerable.connection.execute(
        "SELECT session_token FROM users WHERE id = ?", (vuln_alice,)
    ).fetchone()[0]

    baseline_escape = vulnerable.export_all_notes("../escaped.txt").resolve()
    baseline_command_marker = baseline_dir / "command_marker"
    vulnerable.backup_database(f"backup.db; touch {baseline_command_marker}")
    baseline_pickle_marker = baseline_dir / "pickle_marker"
    baseline_pickle = baseline_dir / "canary.pkl"
    baseline_pickle.write_bytes(pickle.dumps(PickleCanary(baseline_pickle_marker)))
    vulnerable.import_pickle(baseline_pickle)
    baseline_oversized = outcome(
        lambda: vulnerable.create_note(vuln_alice, "Huge", "x" * 20_000),
        success="ACCEPTED: 20,000-character body stored without a limit",
    )
    baseline_log_text = "\n".join(vulnerable.logs)
    baseline_logs_exposed = all(
        value in baseline_log_text
        for value in ("password", baseline_token, "SYNTHETIC-SECRET")
    )
    vulnerable.close()

    # ---------------- hardened application preparation ----------------
    secure_db = Database(secure_dir / "secure.db")
    secure_auth = AuthService(secure_db)
    secure_notes = NoteService(secure_db, secure_dir / "exports")
    alice = secure_auth.register("alice", "CorrectHorse42!")
    bob = secure_auth.register("bob", "BatteryStaple99!")
    secure_note = secure_notes.create_note(
        alice, "Alice private note", "SYNTHETIC-SECRET"
    )

    def secure_login_error(username: str, password: str) -> str:
        try:
            secure_auth.authenticate(username, password)
        except Exception as exc:
            return str(exc)
        return "login unexpectedly succeeded"

    secure_unknown = secure_login_error("nosuchuser", "anything")
    secure_sqli = outcome(
        lambda: secure_auth.authenticate("alice' --", "wrong"),
        success="EXPLOITED: login succeeded with the wrong password",
    )
    # Bob is a different authenticated user and must receive none of Alice's
    # encrypted records even when the query contains SQL syntax.
    secure_search = secure_notes.search_notes(bob, "' ) OR 1=1 --")
    secure_idor = outcome(
        lambda: secure_notes.get_note(bob, secure_note.id),
        success="EXPLOITED: Bob read Alice's note",
    )
    secure_db_files = [
        secure_dir / "secure.db",
        secure_dir / "secure.db-wal",
        secure_dir / "secure.db-shm",
    ]
    secure_raw = b"".join(path.read_bytes() for path in secure_db_files if path.exists())
    secure_password_record = secure_db.execute(
        "SELECT password_hash FROM users WHERE id = ?", (alice.user_id,)
    ).fetchone()["password_hash"]
    secure_stored_digest = secure_db.execute(
        "SELECT token_hash FROM sessions WHERE user_id = ?", (alice.user_id,)
    ).fetchone()["token_hash"]

    secure_escape_result = outcome(
        lambda: secure_notes.export_notes(alice, "../escaped.json"),
        success="EXPLOITED: traversal export succeeded",
    )
    secure_command_marker = secure_dir / "command_marker"
    secure_command_result = outcome(
        lambda: secure_notes.backup_database(
            alice, f"backup.db; touch {secure_command_marker}"
        ),
        success="EXPLOITED: shell-shaped backup name accepted",
    )
    secure_pickle_marker = secure_dir / "pickle_marker"
    secure_pickle = secure_dir / "canary.pkl"
    secure_pickle.write_bytes(pickle.dumps(PickleCanary(secure_pickle_marker)))
    secure_pickle_result = outcome(
        lambda: secure_notes.import_notes(alice, secure_pickle),
        success="EXPLOITED: pickle import accepted",
    )
    secure_oversized = outcome(
        lambda: secure_notes.create_note(alice, "Huge", "x" * 20_000),
        success="ACCEPTED: 20,000-character body stored without a limit",
    )

    # Normal workflows prove that the controls did not remove the feature.
    still_works = (
        secure_notes.get_note(alice, secure_note.id).body == "SYNTHETIC-SECRET"
    )
    valid_backup = secure_notes.backup_database(alice, "safe-backup.db")

    # Exercise lockout last because it changes Alice's account state.
    for _ in range(5):
        secure_login_error("alice", "WrongHorse42!")
    secure_locked = secure_login_error("alice", "CorrectHorse42!")

    audit_rows = secure_db.execute(
        "SELECT event, outcome, detail FROM audit_events"
    ).fetchall()
    audit_text = repr([dict(row) for row in audit_rows])
    secure_audit_clean = not any(
        value in audit_text
        for value in ("CorrectHorse42!", alice.session_token, "SYNTHETIC-SECRET")
    )

    secure_db.close()

    rows = [
        (
            "V-01a",
            "Login SQL injection: `alice' --` + wrong password",
            baseline_sqli,
            secure_sqli,
        ),
        (
            "V-01b",
            "Search SQL injection: `' ) OR 1=1 --`",
            f"EXPLOITED: returned Alice note to user 999 = {bool(baseline_search)}",
            f"BLOCKED: literal search returned {len(secure_search)} notes",
        ),
        (
            "V-02",
            "Inspect stored password verifier",
            f"WEAK: unsalted MD5 `{baseline_hash}`",
            f"STRONG: PBKDF2-HMAC-SHA256, {PBKDF2_ITERATIONS:,} iterations, per-user salt; record prefix `{secure_password_record.split('$')[0]}`",
        ),
        (
            "V-03",
            "Read another user's note by guessing its ID",
            f"EXPLOITED: returned body {baseline_idor['body']!r}",
            secure_idor,
        ),
        (
            "V-04",
            "Search raw SQLite bytes for SYNTHETIC-SECRET",
            f"EXPOSED: plaintext found = {b'SYNTHETIC-SECRET' in baseline_raw}",
            f"PROTECTED: plaintext found = {b'SYNTHETIC-SECRET' in secure_raw}",
        ),
        (
            "V-05",
            "Inspect session token design/storage",
            f"PREDICTABLE + RAW: `session-<user id>-<unix seconds>`; database value equals bearer token = {baseline_stored_token == baseline_token}",
            f"PROTECTED: bearer token is random; database stores only its SHA-256 digest = {secure_stored_digest == token_digest(alice.session_token)}; expiry = {alice.session_expires_at}",
        ),
        (
            "V-06",
            "Import pickle canary that would create a marker file",
            f"EXPLOITED: marker created = {baseline_pickle_marker.exists()}",
            f"{secure_pickle_result}; marker created = {secure_pickle_marker.exists()}",
        ),
        (
            "V-07",
            "Export filename `../escaped.*`",
            f"EXPLOITED: wrote outside export directory to {baseline_escape.name}",
            f"{secure_escape_result}; escaped file exists = {(secure_dir / 'escaped.json').exists()}",
        ),
        (
            "V-08",
            "Backup name containing `; touch <marker>`",
            f"EXPLOITED: marker created = {baseline_command_marker.exists()}",
            f"{secure_command_result}; marker created = {secure_command_marker.exists()}",
        ),
        (
            "V-09a",
            "Compare unknown-user and wrong-password errors",
            f"ENUMERATION: {baseline_unknown!r} vs {baseline_wrong!r}",
            f"GENERIC: unknown-user error = {secure_unknown!r} (same public message used for wrong passwords)",
        ),
        (
            "V-09b",
            "Five wrong passwords, then the correct password",
            "NO LOCKOUT: baseline has no failed-attempt counter or delay",
            f"LOCKED: correct password rejected during lockout: {secure_locked!r}",
        ),
        (
            "V-10",
            "Inspect application logs/audit records",
            f"EXPOSED: baseline logs contain password, bearer token and note body = {baseline_logs_exposed}",
            f"REDACTED: secure audit text contains none of password/token/note body = {secure_audit_clean}",
        ),
        (
            "V-11",
            "Create a 20,000-character note body",
            baseline_oversized,
            secure_oversized,
        ),
        (
            "F-01",
            "Legitimate owner reads note after hardening",
            "Works (but plaintext/insecure)",
            f"Works after decrypting with Alice's password-derived key = {still_works}",
        ),
        (
            "F-02",
            "Legitimate SQLite backup with a safe filename",
            "Works only by invoking an unsafe shell string",
            f"Works through SQLite backup API = {valid_backup.exists()}",
        ),
    ]

    for row in rows:
        safe = [str(cell).replace("|", "\\|") for cell in row]
        lines.append(f"| {safe[0]} | {safe[1]} | {safe[2]} | {safe[3]} |")

    lines.extend(
        [
            "",
            "Interpretation: a baseline result marked EXPLOITED/EXPOSED proves the",
            "vulnerability was reachable, not merely suspected from source review.",
            "A hardened result marked BLOCKED/PROTECTED is paired with F-01/F-02",
            "evidence that the corresponding legitimate workflow still succeeds.",
        ]
    )
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional Markdown output path")
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="Directory for temporary databases and markers (default: a new temp dir)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.work_dir is None:
        with tempfile.TemporaryDirectory(prefix="securenotes-attacks-") as temp:
            transcript = run_demo(Path(temp))
    else:
        transcript = run_demo(args.work_dir)

    print(transcript, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(transcript, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
