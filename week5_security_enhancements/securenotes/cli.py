"""Command-line interface for the hardened SecureNotes application."""

from __future__ import annotations

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

from .auth import AuthService
from .db import Database
from .errors import AppError, ValidationError
from .service import Note, NoteService


def default_db_path() -> Path:
    return Path(os.environ.get("SECURENOTES_DB", "data/securenotes.db"))


def default_export_dir() -> Path:
    return Path(os.environ.get("SECURENOTES_EXPORT_DIR", "data/exports"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securenotes", description="Hardened local notes CLI")
    parser.add_argument("--db", type=Path, default=default_db_path())
    parser.add_argument("--export-dir", type=Path, default=default_export_dir())
    sub = parser.add_subparsers(dest="command", required=True)

    register = sub.add_parser("register", help="create an account")
    register.add_argument("--username", required=True)

    login = sub.add_parser("login", help="verify credentials and issue a session token")
    login.add_argument("--username", required=True)

    whoami = sub.add_parser("whoami", help="validate a session token")
    whoami.add_argument(
        "--token",
        help="session token (prefer omitting this and using the hidden prompt)",
    )

    logout = sub.add_parser("logout", help="revoke a session token")
    logout.add_argument(
        "--token",
        help="session token (prefer omitting this and using the hidden prompt)",
    )

    add = sub.add_parser("add", help="create an encrypted note")
    add.add_argument("--username", required=True)
    add.add_argument("--title", required=True)
    body = add.add_mutually_exclusive_group(required=True)
    body.add_argument("--body", help="note body (prefer --body-file for sensitive text)")
    body.add_argument("--body-file", type=Path, help="UTF-8 file containing the body")
    add.add_argument("--tags", default="")

    list_cmd = sub.add_parser("list", help="list your note titles")
    list_cmd.add_argument("--username", required=True)

    get = sub.add_parser("get", help="display one of your notes")
    get.add_argument("--username", required=True)
    get.add_argument("--id", type=int, required=True)

    search = sub.add_parser("search", help="literal search within your notes")
    search.add_argument("--username", required=True)
    search.add_argument("--query", required=True)

    update = sub.add_parser("update", help="update one of your notes")
    update.add_argument("--username", required=True)
    update.add_argument("--id", type=int, required=True)
    update.add_argument("--title")
    update.add_argument("--body")
    update.add_argument("--tags")

    delete = sub.add_parser("delete", help="delete one of your notes")
    delete.add_argument("--username", required=True)
    delete.add_argument("--id", type=int, required=True)

    export = sub.add_parser("export", help="export your notes as JSON in the export directory")
    export.add_argument("--username", required=True)
    export.add_argument("filename")

    import_cmd = sub.add_parser("import", help="import schema-validated JSON notes")
    import_cmd.add_argument("--username", required=True)
    import_cmd.add_argument("path", type=Path)

    backup = sub.add_parser("backup", help="create a protected SQLite backup")
    backup.add_argument("--username", required=True)
    backup.add_argument("filename")

    change = sub.add_parser("change-password", help="change password and re-encrypt notes")
    change.add_argument("--username", required=True)
    return parser


def _password(prompt: str = "Password: ") -> str:
    return getpass.getpass(prompt)


def _confirmed_password() -> str:
    first = _password("New password: ")
    second = _password("Confirm password: ")
    if first != second:
        raise ValidationError("Passwords do not match.")
    return first


def _session_token(args: argparse.Namespace) -> str:
    """Read a bearer token without requiring it in shell history.

    ``--token`` remains available for controlled automation, but interactive
    users should omit it and answer the hidden prompt instead.
    """

    return args.token or getpass.getpass("Session token: ")


def _authenticate(auth: AuthService, username: str):
    return auth.authenticate(username, _password())


def _print_note(note: Note, *, body: bool = False) -> None:
    tags = ", ".join(note.tags) if note.tags else "-"
    print(f"#{note.id} {note.title} [tags: {tags}]")
    if body:
        print(note.body)


def _read_body(args: argparse.Namespace) -> str:
    if args.body_file is not None:
        if not args.body_file.is_file() or args.body_file.stat().st_size > 20_000:
            raise ValidationError("Body file must exist and be no larger than 20 KB.")
        return args.body_file.read_text(encoding="utf-8")
    return args.body


def run(args: argparse.Namespace) -> int:
    db = Database(args.db)
    auth = AuthService(db)
    notes = NoteService(db, args.export_dir)
    try:
        if args.command == "register":
            context = auth.register(args.username, _confirmed_password())
            print(f"Account created for {context.username}.")
            print(f"Session token (store safely): {context.session_token}")
            print(f"Session expires: {context.session_expires_at}")
        elif args.command == "login":
            context = _authenticate(auth, args.username)
            print(f"Welcome, {context.username}.")
            print(f"Session token (store safely): {context.session_token}")
            print(f"Session expires: {context.session_expires_at}")
        elif args.command == "whoami":
            info = auth.validate_session(_session_token(args))
            print(f"{info.username} (session expires {info.expires_at})")
        elif args.command == "logout":
            auth.logout(_session_token(args))
            print("Session revoked.")
        elif args.command == "add":
            context = _authenticate(auth, args.username)
            note = notes.create_note(context, args.title, _read_body(args), args.tags)
            print(f"Created encrypted note #{note.id}.")
        elif args.command == "list":
            context = _authenticate(auth, args.username)
            found = notes.list_notes(context)
            if not found:
                print("No notes.")
            for note in found:
                _print_note(note)
        elif args.command == "get":
            context = _authenticate(auth, args.username)
            _print_note(notes.get_note(context, args.id), body=True)
        elif args.command == "search":
            context = _authenticate(auth, args.username)
            found = notes.search_notes(context, args.query)
            if not found:
                print("No matching notes.")
            for note in found:
                _print_note(note)
        elif args.command == "update":
            context = _authenticate(auth, args.username)
            note = notes.update_note(
                context,
                args.id,
                title=args.title,
                body=args.body,
                tags=args.tags,
            )
            print(f"Updated note #{note.id}.")
        elif args.command == "delete":
            context = _authenticate(auth, args.username)
            notes.delete_note(context, args.id)
            print(f"Deleted note #{args.id}.")
        elif args.command == "export":
            context = _authenticate(auth, args.username)
            path = notes.export_notes(context, args.filename)
            print(f"Export written to {path} (contains decrypted notes; protect it).")
        elif args.command == "import":
            context = _authenticate(auth, args.username)
            count = notes.import_notes(context, args.path)
            print(f"Imported {count} notes.")
        elif args.command == "backup":
            context = _authenticate(auth, args.username)
            path = notes.backup_database(context, args.filename)
            print(f"Backup written to {path}.")
        elif args.command == "change-password":
            current = _password("Current password: ")
            context = auth.authenticate(args.username, current)
            new_password = _confirmed_password()
            auth.change_password(context, current, new_password)
            print("Password changed and notes re-encrypted. Previous sessions were revoked.")
        return 0
    finally:
        db.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except AppError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception:
        reference = secrets.token_hex(4)
        print(f"Error: An unexpected problem occurred. Reference: {reference}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
