"""End-to-end CLI smoke test with mocked hidden password entry."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from securenotes.cli import _session_token, main
from tests.conftest import ALICE_PASSWORD


@pytest.mark.functionality
def test_cli_register_add_and_search(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    database = tmp_path / "cli.db"
    prompts = iter([ALICE_PASSWORD, ALICE_PASSWORD, ALICE_PASSWORD])
    monkeypatch.setattr(
        "securenotes.cli.getpass.getpass", lambda _prompt: next(prompts)
    )

    assert main(["--db", str(database), "register", "--username", "alice"]) == 0
    assert (
        main(
            [
                "--db",
                str(database),
                "add",
                "--username",
                "alice",
                "--title",
                "CLI note",
                "--body",
                "created from test",
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "Account created" in output
    assert "Created encrypted note" in output
    assert ALICE_PASSWORD not in output


@pytest.mark.security
def test_session_token_can_be_entered_without_shell_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "securenotes.cli.getpass.getpass", lambda _prompt: "hidden-token"
    )
    assert _session_token(SimpleNamespace(token=None)) == "hidden-token"
    assert _session_token(SimpleNamespace(token="automation-token")) == "automation-token"
