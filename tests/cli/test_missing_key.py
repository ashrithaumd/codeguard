"""The unset-ANTHROPIC_API_KEY startup path.

Two levels, deliberately. The subprocess test is the one that actually
proves the user-visible contract — a real interpreter, a real argparse
run, a real exit status, and nothing on stderr but the one line — because
that is the only way to prove the *absence* of a traceback: an in-process
pytest.raises(SystemExit) would pass even if pydantic's ValidationError
were still being printed on the way out. The in-process tests then pin
the edges (empty string counts as missing; a present-but-invalid key does
not) without paying for an interpreter each.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

from codeguard.config import MISSING_ANTHROPIC_KEY_MESSAGE, get_settings, verify_required_settings


@pytest.fixture
def no_key_env(monkeypatch, tmp_path):
    """No key in the environment, and a cwd with no .env to find.

    Both halves matter: Settings has env_file=".env", so deleting the
    variable while pytest runs from the repo root would still load the
    developer's real key and the test would silently prove nothing.

    get_settings() is lru_cache'd, so the cache is cleared on the way in
    (a previous test may have cached a valid Settings) and on the way out
    (this test caches nothing for the next one).
    """
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_cli_without_a_key_prints_one_line_and_exits_2(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    result = subprocess.run(
        [sys.executable, "-m", "codeguard.cli", "audit", "."],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 2
    assert result.stderr.strip() == MISSING_ANTHROPIC_KEY_MESSAGE
    assert "Traceback" not in result.stderr
    assert "ValidationError" not in result.stderr


def test_help_still_works_without_a_key(tmp_path):
    """--help must not need a key. The check runs after parse_args for
    exactly this reason: telling someone how to use the tool is not work
    that needs credentials."""
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    result = subprocess.run(
        [sys.executable, "-m", "codeguard.cli", "--help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode == 0
    assert "audit" in result.stdout


def test_verify_exits_when_the_key_is_missing(no_key_env, capsys):
    with pytest.raises(SystemExit) as exc:
        verify_required_settings()

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.err.strip() == MISSING_ANTHROPIC_KEY_MESSAGE
    assert captured.out == ""


def test_an_empty_key_counts_as_missing(no_key_env, monkeypatch, capsys):
    """`export ANTHROPIC_API_KEY=` sets the variable to "". pydantic is
    satisfied — the field is present — so this case only fails later, at
    the first 401. Treated as unset."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "   ")
    get_settings.cache_clear()

    with pytest.raises(SystemExit) as exc:
        verify_required_settings()

    assert exc.value.code == 2
    assert capsys.readouterr().err.strip() == MISSING_ANTHROPIC_KEY_MESSAGE


def test_an_invalid_key_is_not_this_checks_business(no_key_env, monkeypatch, capsys):
    """The degraded path is unchanged: a present-but-wrong key starts
    normally and fails at the Anthropic call, where the 401 says so. This
    check only ever answers "is it set", never "does it work" — an error
    line claiming the key is unset when it is merely revoked would send
    the user looking in the wrong place."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-not-a-real-key")
    get_settings.cache_clear()

    verify_required_settings()

    assert capsys.readouterr().err == ""
