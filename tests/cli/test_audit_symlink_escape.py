"""A repository must not be able to read files outside itself.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
cli.py's _collect_repo_files walks the clone with os.walk and then calls
abs_path.read_text() with no symlink check and no containment check.

A repository containing a symlink named like ordinary source --
`config.py -> /app/.env`, or `/proc/self/environ`, or the mounted GitHub
App private key -- is:

  1. classified as reviewable BY PATH (`config.py` passes
     is_reviewable_path before anything touches disk), then
  2. read with read_text(), WHICH FOLLOWS THE LINK, then
  3. placed in files[rel_path] and carried into the scanners, the LLM
     prompt, the findings, the stored report, and the rendered page.

Any signed-in visitor chooses the repository, so this is the whole worker
filesystem readable on request. It is the highest-priority control in
Stage 1.

os.walk defaults to followlinks=False, so a symlinked DIRECTORY is not
descended into. That narrows the hole to files; it does not close it,
because a symlinked file appears in `filenames` and read_text() follows it.

WHAT THE TESTS ASSERT
The sentinel value must appear in NONE of: the returned findings, the
written report, the log output, or the content handed to the model. A
control file in the same repo must still be reviewed, so a passing test
cannot be explained by the audit having skipped everything.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from codeguard.cli import _collect_repo_files, run_audit
from codeguard.config import RepoConfig

SENTINEL = "SENTINEL_STOLEN_SECRET_e3b0c44298fc"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX symlink semantics; the deployment is Linux",
)


@pytest.fixture
def repo_with_escape(tmp_path):
    """A repo whose `settings.py` is a symlink to a file outside it.

    The secret file is a sibling of the repo rather than a real /app/.env,
    so the test is hermetic and does not depend on the container layout.
    The mechanism is identical: a relative or absolute link whose target
    resolves outside the clone root.
    """
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "dot_env"
    secret.write_text(f"ANTHROPIC_API_KEY={SENTINEL}\n", encoding="utf-8")

    repo = tmp_path / "repo"
    repo.mkdir()
    # Control: a real file that MUST still be reviewed.
    (repo / "real_module.py").write_text(
        "import sqlite3\n\n"
        "def q(c, name):\n"
        "    c.execute('SELECT * FROM t WHERE n = %s' % name)\n",
        encoding="utf-8",
    )
    # The escape: named like source, points outside the tree.
    os.symlink(secret, repo / "settings.py")
    # A second shape: relative traversal rather than an absolute path.
    os.symlink("../outside/dot_env", repo / "conf.py")
    return repo, secret


def test_collect_repo_files_does_not_read_through_a_symlink(repo_with_escape):
    """The unit-level assertion, closest to the defect."""
    repo, _ = repo_with_escape
    files, _deps, _patches = _collect_repo_files(repo, RepoConfig())

    joined = "\n".join(files.values())
    assert SENTINEL not in joined, "read through a symlink out of the clone"
    assert "settings.py" not in files, "the absolute-path link must be skipped"
    assert "conf.py" not in files, "the relative traversal link must be skipped"
    assert "real_module.py" in files, "a real file must still be collected"


def test_an_audit_never_reports_the_escaped_secret(repo_with_escape, tmp_path, capsys):
    """End to end through run_audit: findings, report, and stderr."""
    repo, _ = repo_with_escape
    out = tmp_path / "report.md"

    # No LLM: the verdict layer is irrelevant to whether the file was READ,
    # and stubbing it keeps the test free and deterministic.
    with patch("codeguard.cli._run_verdict_layer") as verdict:
        verdict.return_value = type(
            "V", (), {"confirmed": [], "dismissed": [], "claimed_files": set(),
                      "tokens_in": 0, "tokens_out": 0, "cost": 0.0,
                      "call_failures": []},
        )()
        exit_code, error = run_audit(str(repo), str(out), False)

    assert error is None, f"the audit should have completed: {error}"
    report = out.read_text(encoding="utf-8")
    assert SENTINEL not in report, "the secret reached the stored report"
    assert SENTINEL not in capsys.readouterr().err, "the secret reached stderr"


def test_the_model_never_receives_the_escaped_secret(repo_with_escape, tmp_path):
    """The sink that matters most, because it leaves our infrastructure.

    Captures what would be sent to Anthropic by intercepting the content
    at the point the audit hands files to the verdict layer.
    """
    repo, _ = repo_with_escape
    seen: list[str] = []

    def capture(agent, kind, name, files, findings_by_file, **kw):
        seen.extend(files.values())
        return type(
            "V", (), {"confirmed": [], "dismissed": [], "claimed_files": set(),
                      "tokens_in": 0, "tokens_out": 0, "cost": 0.0,
                      "call_failures": []},
        )()

    with patch("codeguard.cli._run_verdict_layer", side_effect=capture):
        run_audit(str(repo), str(tmp_path / "r.md"), False)

    assert seen, "the verdict layer should have been given at least one file"
    assert SENTINEL not in "\n".join(seen), "the secret was handed to the model"


def test_a_special_file_is_skipped_without_hanging(tmp_path):
    """A FIFO named like source blocks read_text() FOREVER.

    Same class as the symlink: the walk must ask what a path IS before
    reading it, not only what it is called. This is a denial of service on
    the worker from a repository -- one file, and that worker replica never
    finishes another job.

    Run in a thread with a join timeout so a regression FAILS instead of
    hanging the suite. Before the fix this test times out; a hung test that
    never reports is the worst of both worlds, and the daemon thread is
    abandoned to the interpreter rather than leaked into later tests.
    """
    import threading

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "ok.py").write_text("x = 1\n", encoding="utf-8")
    os.mkfifo(repo / "pipe.py")

    result: dict = {}

    def run():
        result["files"] = _collect_repo_files(repo, RepoConfig())[0]

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=15)

    assert not thread.is_alive(), "reading a FIFO blocked the walk (worker DoS)"
    assert "pipe.py" not in result["files"]
    assert "ok.py" in result["files"]


def test_a_symlink_inside_the_repo_is_still_skipped(tmp_path):
    """Deliberately strict: an in-tree symlink is skipped too.

    Its target is already collected on its own, so following it would only
    duplicate content and double the tokens paid for it. Skipping every
    symlink keeps the rule one line long and impossible to get subtly
    wrong -- "is it a link" rather than "where does it point, and is that
    still inside after every component is resolved".
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "real.py").write_text("y = 2\n", encoding="utf-8")
    os.symlink(repo / "real.py", repo / "alias.py")

    files, _deps, _patches = _collect_repo_files(repo, RepoConfig())

    assert "real.py" in files
    assert "alias.py" not in files


def test_clone_flags_disable_symlinks_and_hooks():
    """The first layer: git is told not to materialise links at all.

    Asserted on the argv rather than by cloning, so it is fast and does
    not need the network. Defence in depth with the walk check --
    core.symlinks=false writes a plain text file containing the target
    path, which is inert, and the walk check catches anything created
    between clone and read.
    """
    from codeguard.cli import _clone_shallow

    with patch("codeguard.cli.subprocess.run") as run:
        run.return_value = type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        _clone_shallow("https://github.com/o/r", Path("/tmp/x"))

    argv = run.call_args[0][0]
    joined = " ".join(argv)
    assert "core.symlinks=false" in joined
    assert "core.hooksPath=/dev/null" in joined
    assert "protocol.file.allow=never" in joined
    assert "--no-recurse-submodules" in joined
    assert "--depth" in joined
    env = run.call_args[1].get("env") or {}
    assert env.get("GIT_TERMINAL_PROMPT") == "0"
    assert env.get("GIT_LFS_SKIP_SMUDGE") == "1"
