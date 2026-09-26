"""An audit must stop by its deadline, and stop for real.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
Two problems, one of which the original plan got wrong.

1. `max_wall_clock_s` was CONSTRUCTED AND NEVER ENFORCED. grep for it
   across codeguard/ returns only the two places that build a Budget --
   cli.py:133 and cli.py:625 -- and nothing that reads it. An audit of a
   pathological repository ran until the scanners' own per-tool timeouts
   and the model's own per-call timeouts happened to add up to a stop.

2. The plan proposed enforcing it with asyncio.wait_for around
   asyncio.to_thread. That does not work, and the plan's own section 4
   says why: cancelling a to_thread task does NOT stop the thread. The
   coroutine raises CancelledError, the audit is marked timed out, and the
   thread KEEPS CLONING AND KEEPS CALLING ANTHROPIC -- so the deadline
   would report a stop it had not achieved, while still spending money.

So the deadline lives INSIDE run_audit: checked between stages and before
every model call, with the clone given its own subprocess timeout. The
outer wait_for stays only as a backstop for a thread wedged somewhere
with no checkpoint.

WHAT THE TESTS ASSERT
That no LLM call happens after the deadline has passed -- which is the
only assertion that distinguishes "we stopped" from "we said we stopped".
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from codeguard.cli import AuditStats, DeadlineExceeded, _Deadline, run_audit


def test_a_deadline_reports_remaining_and_expiry():
    d = _Deadline(0.05)
    assert not d.expired
    assert d.remaining > 0
    time.sleep(0.06)
    assert d.expired
    assert d.remaining == 0


def test_check_raises_once_expired():
    d = _Deadline(0.01)
    d.check("before the scanners")          # fine
    time.sleep(0.02)
    with pytest.raises(DeadlineExceeded) as caught:
        d.check("before the verdict layer")
    assert "before the verdict layer" in str(caught.value)


def test_a_disabled_deadline_never_expires():
    """0 or None means no limit, for the CLI and MCP paths that had none."""
    d = _Deadline(0)
    time.sleep(0.01)
    assert not d.expired
    d.check("anything")


def test_no_model_call_happens_after_the_deadline(tmp_path):
    """The assertion the amendment asked for, and the one that matters.

    The repo is real and reviewable, the tools run for real, and the
    deadline is set so short that it has already passed by the time the
    verdict layer would be reached. If a single verdict call is made, the
    limit is decorative.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text(
        "import sqlite3\n\ndef q(c, n):\n    c.execute('SELECT %s' % n)\n",
        encoding="utf-8",
    )

    calls: list[str] = []

    def spy(agent, kind, name, files, findings_by_file, **kw):
        calls.append(name)
        raise AssertionError("a verdict call was made after the deadline")

    with patch("codeguard.cli._run_verdict_layer", side_effect=spy):
        exit_code, error = run_audit(
            str(repo), str(tmp_path / "r.md"), False, deadline_s=0.001,
        )

    assert calls == [], "no model call may happen once the deadline has passed"
    assert exit_code == 1
    assert error is not None
    assert "too long" in error.lower() or "time" in error.lower()


def test_the_timeout_message_is_for_a_person_not_a_log(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text("x = 1\n", encoding="utf-8")

    _code, error = run_audit(str(repo), str(tmp_path / "r.md"), False, deadline_s=0.001)

    assert "Traceback" not in error
    assert "DeadlineExceeded" not in error, "no exception class names in user-facing text"
    assert error.endswith(".") or error.endswith(")")


def test_stats_still_report_what_was_spent_before_the_deadline(tmp_path):
    """A timeout is not a reason to lose the accounting: whatever was spent
    before the clock ran out was still spent."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text("x = 1\n", encoding="utf-8")

    stats = AuditStats()
    run_audit(str(repo), str(tmp_path / "r.md"), False, stats, deadline_s=0.001)

    # Nothing was spent here because no call was reached, but the object
    # must be populated rather than left at a sentinel.
    assert stats.duration_s > 0


def test_a_generous_deadline_does_not_interfere(tmp_path):
    """The limit must not fire on an ordinary audit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "m.py").write_text("x = 1\n", encoding="utf-8")

    with patch("codeguard.cli._run_verdict_layer") as verdict:
        verdict.return_value = type(
            "V", (), {"confirmed": [], "dismissed": [], "claimed_files": set(),
                      "tokens_in": 0, "tokens_out": 0, "cost": 0.0,
                      "call_failures": []},
        )()
        exit_code, error = run_audit(
            str(repo), str(tmp_path / "r.md"), False, deadline_s=300,
        )

    assert error is None
    assert exit_code == 0


def test_the_clone_gets_its_own_subprocess_timeout():
    """The clone cannot be interrupted by a Python-level check, so it needs
    git's own timeout -- and it must not exceed what is left of the audit's
    deadline."""
    from codeguard.cli import CLONE_TIMEOUT_S, _clone_shallow

    with patch("codeguard.cli.subprocess.run") as run:
        run.return_value = type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
        _clone_shallow("https://github.com/o/r", tmp := __import__("pathlib").Path("/tmp/x"))
        assert run.call_args[1]["timeout"] == CLONE_TIMEOUT_S

        run.reset_mock()
        _clone_shallow("https://github.com/o/r", tmp, timeout=7)
        assert run.call_args[1]["timeout"] == 7


def test_a_repo_with_no_python_stops_before_any_model_call(tmp_path):
    """"CodeGuard currently analyzes Python repositories."

    Checked after the walk and BEFORE the scanners, so a repository of
    nothing but Markdown costs one clone and nothing else -- no scanner
    subprocesses, and above all no LLM call to pay for.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("# just docs\n", encoding="utf-8")
    (repo / "notes.txt").write_text("nothing here\n", encoding="utf-8")

    calls: list[str] = []

    def spy(agent, kind, name, files, findings_by_file, **kw):
        calls.append(name)
        raise AssertionError("a verdict call was made on a repo with no Python")

    with patch("codeguard.cli._run_verdict_layer", side_effect=spy):
        exit_code, error = run_audit(str(repo), str(tmp_path / "r.md"), False)

    assert calls == []
    assert exit_code == 1
    assert "Python" in error
    assert "Traceback" not in error
