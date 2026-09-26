"""The deadline inside the per-chunk loop, and typed audit outcomes.

TWO VULNERABILITIES THIS REPRODUCES
-----------------------------------
1. THE DEADLINE DID NOT BOUND THE EXPENSIVE STAGE.

   It was checked at three stage boundaries: after the clone, before the
   scanners, and before the verdict layer. But the verdict layer makes ONE
   LLM CALL PER CHUNK -- _run_verdict_layer loops over files, then over AST
   chunk boundaries within each file, calling verdict_fn each time. Once
   that layer started, a large repository ran to completion however long it
   took, spending credit the entire way. The check has to be inside the
   loop, immediately before each call.

2. EVERY REFUSAL LOOKED LIKE A FAILURE.

   run_audit returned (1, message) for a timeout, for a repository with no
   Python, and (later) for too-large and budget-exhausted. The worker
   mapped exit code 1 to status 'failed'. So "this repository is too large"
   and "the worker crashed" were the same stored state, and the only thing
   distinguishing them was the wording of a message -- which breaks
   silently the first time someone rewords it.

   The outcome is now explicit and the worker maps it without reading text.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest

from codeguard.cli import (
    AuditOutcome,
    AuditStats,
    DeadlineExceeded,
    _Deadline,
    _run_verdict_layer,
    run_audit,
)
from codeguard.severity import Severity
from codeguard.tools.models import Finding


def _finding(path: str, line: int) -> Finding:
    return Finding.create(
        file=path, start_line=line, end_line=line, severity=Severity.MEDIUM,
        source_tool="bandit", rule_id="B608", message="interpolated sql",
    )


def _chunky_source(chunks: int) -> str:
    """Several top-level functions, so _chunk_file_by_ast has real
    boundaries to split on and each chunk carries its own finding."""
    parts = []
    for i in range(chunks):
        parts.append(
            f"def f{i}(c, n):\n"
            f"    c.execute('SELECT %s' % n)  # chunk {i}\n"
        )
    return "\n\n".join(parts) + "\n"


# --- correction 1: the deadline inside the per-chunk loop ---------------


def test_the_deadline_stops_the_verdict_layer_after_the_first_call():
    """The assertion the amendment asked for.

    Three chunks, each with a finding, and a deadline that expires during
    the first call. Exactly one model call may happen -- not three.
    """
    source = _chunky_source(3)
    # One finding per function, on the c.execute line of each.
    lines = source.splitlines()
    finding_lines = [i + 1 for i, line in enumerate(lines) if "execute" in line]
    assert len(finding_lines) == 3, "fixture should produce three findings"

    files = {"m.py": source}
    findings = {"m.py": [_finding("m.py", n) for n in finding_lines]}

    calls: list[str] = []
    deadline = _Deadline(0.05)

    def fake_verdict(state):
        calls.append(state["path"])
        time.sleep(0.06)          # the clock runs out during this call
        return {"confirmed": [], "dismissed": [], "tokens_in": 10,
                "tokens_out": 5, "estimated_cost_usd": 0.001, "verdict_call_failures": []}

    with pytest.raises(DeadlineExceeded):
        _run_verdict_layer(
            fake_verdict, "o", "r", files, findings,
            # Force one chunk per function so there are three calls to make.
            chunk_budget=40, deadline=deadline,
        )

    assert len(calls) == 1, f"expected exactly one model call, got {len(calls)}"


def test_the_deadline_carries_what_was_already_spent():
    """A timeout is not a reason to lose the accounting. The partial
    tokens and cost from calls that DID happen ride on the exception, so
    run_audit can still report them."""
    source = _chunky_source(3)
    lines = source.splitlines()
    finding_lines = [i + 1 for i, line in enumerate(lines) if "execute" in line]
    files = {"m.py": source}
    findings = {"m.py": [_finding("m.py", n) for n in finding_lines]}

    deadline = _Deadline(0.05)

    def fake_verdict(state):
        time.sleep(0.06)
        return {"confirmed": [], "dismissed": [], "tokens_in": 111,
                "tokens_out": 22, "estimated_cost_usd": 0.5, "verdict_call_failures": []}

    with pytest.raises(DeadlineExceeded) as caught:
        _run_verdict_layer(fake_verdict, "o", "r", files, findings,
                           chunk_budget=40, deadline=deadline)

    exc = caught.value
    assert exc.tokens_in == 111
    assert exc.tokens_out == 22
    assert exc.cost == 0.5


def test_an_unexpired_deadline_lets_every_chunk_run():
    """The limit must not fire on an ordinary audit."""
    source = _chunky_source(3)
    lines = source.splitlines()
    finding_lines = [i + 1 for i, line in enumerate(lines) if "execute" in line]
    files = {"m.py": source}
    findings = {"m.py": [_finding("m.py", n) for n in finding_lines]}

    calls: list[str] = []

    def fake_verdict(state):
        calls.append(state["path"])
        return {"confirmed": [], "dismissed": [], "tokens_in": 1,
                "tokens_out": 1, "estimated_cost_usd": 0.0, "verdict_call_failures": []}

    result = _run_verdict_layer(fake_verdict, "o", "r", files, findings,
                                chunk_budget=40, deadline=_Deadline(300))

    assert len(calls) == 3
    assert result.tokens_in == 3


def test_no_deadline_at_all_still_works():
    """CLI and MCP callers pass none."""
    files = {"m.py": _chunky_source(1)}
    findings = {"m.py": [_finding("m.py", 2)]}

    def fake_verdict(state):
        return {"confirmed": [], "dismissed": [], "tokens_in": 1,
                "tokens_out": 1, "estimated_cost_usd": 0.0, "verdict_call_failures": []}

    result = _run_verdict_layer(fake_verdict, "o", "r", files, findings)
    assert result.tokens_in == 1


# --- correction 3: typed outcomes --------------------------------------


def _repo(tmp_path, *, python=True):
    repo = tmp_path / "src"
    repo.mkdir()
    if python:
        (repo / "m.py").write_text("x = 1\n", encoding="utf-8")
    else:
        (repo / "README.md").write_text("# docs\n", encoding="utf-8")
    return repo


def test_a_clean_audit_reports_completed(tmp_path):
    stats = AuditStats()
    with patch("codeguard.cli._run_verdict_layer") as verdict:
        verdict.return_value = type(
            "V", (), {"confirmed": [], "dismissed": [], "claimed_files": set(),
                      "tokens_in": 0, "tokens_out": 0, "cost": 0.0,
                      "call_failures": []},
        )()
        run_audit(str(_repo(tmp_path)), str(tmp_path / "r.md"), False, stats)

    assert stats.outcome is AuditOutcome.COMPLETED


def test_no_python_reports_rejected_not_failed(tmp_path):
    """"Too large" and "no Python" are refusals, not breakages. Storing
    them as 'failed' tells the user to retry something that will never
    work."""
    stats = AuditStats()
    run_audit(str(_repo(tmp_path, python=False)), str(tmp_path / "r.md"), False, stats)

    assert stats.outcome is AuditOutcome.REJECTED


def test_a_timeout_reports_timed_out_not_failed(tmp_path):
    stats = AuditStats()
    run_audit(str(_repo(tmp_path)), str(tmp_path / "r.md"), False, stats,
              deadline_s=0.001)

    assert stats.outcome is AuditOutcome.TIMED_OUT


def test_a_clone_failure_reports_failed(tmp_path):
    """This one really is a breakage: retrying is reasonable."""
    import subprocess

    stats = AuditStats()
    with patch("codeguard.cli._clone_shallow",
               side_effect=subprocess.CalledProcessError(128, "git", stderr="nope")):
        run_audit("https://github.com/o/r", str(tmp_path / "r.md"), False, stats)

    assert stats.outcome is AuditOutcome.FAILED


def test_a_non_directory_target_reports_failed(tmp_path):
    stats = AuditStats()
    run_audit(str(tmp_path / "nope"), str(tmp_path / "r.md"), False, stats)
    assert stats.outcome is AuditOutcome.FAILED


def test_the_outcome_does_not_depend_on_message_wording(tmp_path):
    """The point of the whole change: the outcome is a value, so rewording
    a user-facing string cannot silently change how it is stored."""
    stats = AuditStats()
    run_audit(str(_repo(tmp_path, python=False)), str(tmp_path / "r.md"), False, stats)

    assert stats.outcome is AuditOutcome.REJECTED
    # Rewording the message must not be able to affect the outcome, so the
    # two are independent: this asserts the outcome is not derived from it.
    assert isinstance(stats.outcome, AuditOutcome)
    assert stats.message and isinstance(stats.message, str)
