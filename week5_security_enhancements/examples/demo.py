"""Non-interactive SecureNotes workflow demonstration.

The production CLI prompts for passwords with ``getpass`` and therefore is
not scripted here.  This example exercises the same AuthService/NoteService
objects used by the CLI so it can be captured as reproducible evidence.
All accounts and note text are synthetic.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from securenotes.auth import AuthService  # noqa: E402
from securenotes.db import Database
from securenotes.errors import AppError
from securenotes.service import NoteService


def run(root: Path) -> None:
    db = Database(root / "demo.db")
    auth = AuthService(db)
    notes = NoteService(db, root / "exports")

    alice = auth.register("alice", "CorrectHorse42!")
    bob = auth.register("bob", "BatteryStaple99!")
    print(f"Registered alice (id={alice.user_id}) and bob (id={bob.user_id})")
    print(f"Alice session expires at {alice.session_expires_at} (token redacted)")

    first = notes.create_note(
        alice, "Project plan", "Call the supplier on Tuesday", ["work"]
    )
    second = notes.create_note(
        alice, "Travel", "Passport copy is in the blue folder", ["personal"]
    )
    print(f"Created encrypted notes #{first.id} and #{second.id}")
    print("Alice list:", [(n.id, n.title) for n in notes.list_notes(alice)])
    print("Alice search 'supplier':", [n.id for n in notes.search_notes(alice, "supplier")])

    try:
        notes.get_note(bob, first.id)
    except AppError as exc:
        print(f"Bob trying to read Alice note #{first.id}: {type(exc).__name__}: {exc}")

    stored = db.execute(
        "SELECT title_ciphertext, body_ciphertext FROM notes WHERE id = ?",
        (first.id,),
    ).fetchone()
    print("Stored title ciphertext (first 24 chars):", stored["title_ciphertext"][:24])
    print("Stored body ciphertext (first 24 chars):", stored["body_ciphertext"][:24])

    export_path = notes.export_notes(alice, "alice-notes.json")
    print(f"Exported Alice-only JSON: {export_path.name} ({export_path.stat().st_size} bytes)")

    auth.change_password(alice, "CorrectHorse42!", "NewBattery42!")
    try:
        auth.authenticate("alice", "CorrectHorse42!")
    except AppError as exc:
        print(f"Old password after rotation: {type(exc).__name__}: {exc}")
    rotated = auth.authenticate("alice", "NewBattery42!")
    print("New password can still decrypt note:", notes.get_note(rotated, first.id).body)
    db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--work-dir",
        type=Path,
        help="Keep demo files in this directory instead of a temporary directory",
    )
    args = parser.parse_args()
    if args.work_dir is None:
        with tempfile.TemporaryDirectory(prefix="securenotes-demo-") as temp:
            run(Path(temp))
    else:
        args.work_dir.mkdir(parents=True, exist_ok=True)
        run(args.work_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
