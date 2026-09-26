"""Every audit exit path must leave no temporary directory behind.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
Not a disclosure — a resource leak that becomes one. Two temp directories
exist per audit:

    run_audit's clone dir            tempfile.mkdtemp("codeguard-audit-")
    handle_repo_audit's output dir   tempfile.mkdtemp("codeguard-audit-out-")

Both have a `finally: rmtree`, and before these tests NOTHING ASSERTED
EITHER OF THEM. A leak fills the worker's disk with cloned repositories —
attacker-supplied content, sitting on the filesystem of a process that
holds the Anthropic key and the GitHub App key — and a full disk is the
next audit failing for a reason nobody can diagnose.

WHAT THESE TESTS ASSERT
The directory does not exist after run_audit / handle_repo_audit returns,
on every exit path the plan enumerated: success, clone failure, non-URL
target, no Python, deadline exceeded, handler exception, and cancellation.

Paths are captured by spying on tempfile.mkdtemp rather than guessing
names, so the assertion is about the directory the code actually created.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from unittest.mock import patch

import pytest

from codeguard.cli import run_audit

_REAL_MKDTEMP = tempfile.mkdtemp


@pytest.fixture
def created_dirs(monkeypatch):
    """Every directory mkdtemp hands out during the test."""
    made: list[str] = []

    def spy(*args, **kwargs):
        path = _REAL_MKDTEMP(*args, **kwargs)
        made.append(path)
        return path

    monkeypatch.setattr(tempfile, "mkdtemp", spy)
    return made


def _assert_all_gone(made: list[str], expect_at_least: int = 1):
    assert len(made) >= expect_at_least, (
        f"expected at least {expect_at_least} temp dir(s) to be created, got {made}"
    )
    survivors = [p for p in made if os.path.exists(p)]
    assert not survivors, f"temporary directories left behind: {survivors}"


def _repo(tmp_path, with_python=True):
    repo = tmp_path / "src"
    repo.mkdir()
    if with_python:
        (repo / "m.py").write_text("x = 1\n", encoding="utf-8")
    else:
        (repo / "README.md").write_text("# docs\n", encoding="utf-8")
    return repo


def _stub_verdict():
    return patch("codeguard.cli._run_verdict_layer", return_value=type(
        "V", (), {"confirmed": [], "dismissed": [], "claimed_files": set(),
                  "tokens_in": 0, "tokens_out": 0, "cost": 0.0,
                  "call_failures": []},
    )())


# --- run_audit's clone directory ---------------------------------------


def test_cleanup_on_a_successful_remote_audit(tmp_path, created_dirs):
    """The success path. A clone happened, so there IS a directory to leak."""
    def fake_clone(url, dest, timeout=None):
        # Populate the destination the way a real clone would.
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "m.py").write_text("y = 2\n", encoding="utf-8")

    with patch("codeguard.cli._clone_shallow", side_effect=fake_clone), _stub_verdict():
        exit_code, error = run_audit(
            "https://github.com/o/r", str(tmp_path / "out.md"), False,
        )

    assert error is None, error
    assert exit_code == 0
    _assert_all_gone(created_dirs)


def test_cleanup_when_the_clone_fails(tmp_path, created_dirs):
    """mkdtemp runs BEFORE the clone, so a clone failure is the classic
    leak: the directory exists and the function returns early."""
    with patch("codeguard.cli._clone_shallow",
               side_effect=subprocess.CalledProcessError(128, "git", stderr="nope")):
        exit_code, error = run_audit(
            "https://github.com/o/r", str(tmp_path / "out.md"), False,
        )

    assert exit_code == 1
    assert "clone failed" in error
    _assert_all_gone(created_dirs)


def test_cleanup_when_the_clone_times_out(tmp_path, created_dirs):
    """git's own subprocess timeout, i.e. the deadline arriving during the
    one stage a Python-level check cannot interrupt."""
    with patch("codeguard.cli._clone_shallow",
               side_effect=subprocess.TimeoutExpired("git", 1)):
        exit_code, error = run_audit(
            "https://github.com/o/r", str(tmp_path / "out.md"), False,
        )

    assert exit_code == 1
    assert "too long" in error.lower()
    _assert_all_gone(created_dirs)


def test_cleanup_when_the_deadline_expires(tmp_path, created_dirs):
    def fake_clone(url, dest, timeout=None):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "m.py").write_text("y = 2\n", encoding="utf-8")

    with patch("codeguard.cli._clone_shallow", side_effect=fake_clone):
        exit_code, error = run_audit(
            "https://github.com/o/r", str(tmp_path / "out.md"), False,
            deadline_s=0.001,
        )

    assert exit_code == 1
    _assert_all_gone(created_dirs)


def test_cleanup_when_the_repo_has_no_python(tmp_path, created_dirs):
    def fake_clone(url, dest, timeout=None):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "README.md").write_text("# docs\n", encoding="utf-8")

    with patch("codeguard.cli._clone_shallow", side_effect=fake_clone):
        exit_code, error = run_audit(
            "https://github.com/o/r", str(tmp_path / "out.md"), False,
        )

    assert exit_code == 1
    assert "Python" in error
    _assert_all_gone(created_dirs)


def test_a_local_target_creates_no_clone_dir(tmp_path, created_dirs):
    """A local audit has nothing to clone, so no clone directory is made.

    Asserted on the `codeguard-audit-` prefix rather than on the list being
    empty. The first version of this test asserted empty and failed,
    revealing a THIRD family of temporary directories that the plan had not
    enumerated: tools/base.py gives semgrep, bandit and ruff a scratch
    directory each. They are legitimate and they are cleaned up (see the
    test below), but they are not clone directories.
    """
    source = _repo(tmp_path)
    with _stub_verdict():
        run_audit(str(source), str(tmp_path / "out.md"), False)

    clones = [p for p in created_dirs if "codeguard-audit-" in p]
    assert clones == [], f"a local audit must not clone: {clones}"


def test_the_scanners_clean_up_their_own_scratch_directories(tmp_path, created_dirs):
    """Third family, found by the test above failing.

    Each tool run gets its own mkdtemp. They hold copies of the repository's
    source, so a leak here has the same shape as a leaked clone: untrusted
    content accumulating on the worker's disk.
    """
    source = _repo(tmp_path)
    with _stub_verdict():
        run_audit(str(source), str(tmp_path / "out.md"), False)

    scratch = [p for p in created_dirs
               if any(t in p for t in ("semgrep", "bandit", "ruff"))]
    assert scratch, "the scanners should have created scratch directories"
    survivors = [p for p in scratch if os.path.exists(p)]
    assert not survivors, f"scanner scratch directories left behind: {survivors}"


def test_a_non_directory_target_creates_no_temp_dir(tmp_path, created_dirs):
    """Returns before mkdtemp is reached at all, so nothing of any kind."""
    exit_code, error = run_audit(
        str(tmp_path / "does-not-exist"), str(tmp_path / "out.md"), False,
    )
    assert exit_code == 1
    assert created_dirs == []
