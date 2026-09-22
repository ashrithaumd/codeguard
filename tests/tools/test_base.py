"""Covers run_tool_on_pr's failure path specifically -- the branch that
decides what an operator and a PR reviewer are told when a tool did not
run at all.

The motivating case is real and reproducible: on Windows, semgrep's CLI
entry point execs a semgrep-core binary that is not shipped for that
platform, dies with FileNotFoundError [Errno 2], and writes nothing to
stdout. The old code discarded stderr, so json.loads("") raised and the
only trace left behind was "semgrep crashed" plus a JSONDecodeError --
an error about THIS module's parsing, describing neither the real cause
nor the consequence (a review with none of the custom llm-security
ruleset applied, still presented as an AI-aware review).
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from unittest.mock import patch

from codeguard.tools.base import UNAVAILABLE_RULE_ID, _exit_status, run_tool_on_pr

FILES = {"a.py": "x = 1"}

# From a real Windows run of the same command the semgrep runner builds
# (interpreter path shortened): empty stdout, the whole traceback on
# stderr.
WINDOWS_SEMGREP_STDERR = r"""Traceback (most recent call last):
  File "C:\Python313\Scripts\semgrep", line 151, in <module>
    exec_osemgrep()
  File "C:\Python313\Scripts\semgrep", line 132, in exec_osemgrep
    os.execvp(str(path), sys.argv)
FileNotFoundError: [Errno 2] No such file or directory
"""


def _run(tool_name, stdout="", stderr=WINDOWS_SEMGREP_STDERR, platform="win32"):
    completed = subprocess.CompletedProcess(args=["x"], returncode=1, stdout=stdout, stderr=stderr)
    with (
        patch("codeguard.tools.base.subprocess.run", return_value=completed),
        patch("codeguard.tools.base.sys.platform", platform),
    ):
        return run_tool_on_pr(
            tool_name, lambda tmp_dir: ["x"], lambda out, tmp_dir: json.loads(out), FILES, timeout=5,
        )


def test_failed_tool_still_returns_one_unavailable_finding_not_an_exception():
    """The original guarantee: a dead tool degrades the review, it never
    aborts it.
    """
    findings = _run("semgrep")

    assert len(findings) == 1
    assert findings[0].rule_id == "internal.tool_unavailable"
    assert findings[0].file == "<pr>"


def test_windows_semgrep_failure_names_the_cause_in_the_finding():
    """The reviewer-facing half. Without the hint this message is
    "semgrep unavailable: Expecting value: line 1 column 1 (char 0)",
    which points at JSON parsing rather than at a tool that cannot run
    on this platform.
    """
    [finding] = _run("semgrep")

    assert "CAUSE" in finding.message
    assert "not shipped for Windows" in finding.message
    assert "no custom llm-security rule coverage" in finding.message.lower()


def test_windows_semgrep_failure_logs_the_tools_own_stderr(caplog):
    """The operator-facing half: the real FileNotFoundError lives only
    in the subprocess's stderr, which used to be thrown away.
    """
    with caplog.at_level(logging.ERROR, logger="codeguard.tools.base"):
        _run("semgrep")

    record = caplog.text
    assert "DID NOT RUN" in record
    assert "FileNotFoundError" in record          # from the captured stderr
    assert "os.execvp" in record                  # ditto -- proves stderr, not just the exception
    assert "no semgrep coverage" in record


def test_hint_is_scoped_to_semgrep_on_windows_only():
    """bandit and ruff ship real Windows executables; attaching
    semgrep's explanation to their failures would be plainly wrong.
    """
    [bandit_on_windows] = _run("bandit")
    assert "CAUSE" not in bandit_on_windows.message

    [semgrep_on_linux] = _run("semgrep", platform="linux")
    assert "CAUSE" not in semgrep_on_linux.message


def test_stderr_is_omitted_cleanly_when_the_tool_wrote_none():
    [finding] = _run("semgrep", stderr="", platform="linux")

    assert finding.rule_id == "internal.tool_unavailable"
    assert "stderr_tail" not in finding.message


# --- exit status on the failure path ------------------------------------


def test_exit_status_names_a_signal_kill():
    """The shape that made the 2026-09-22 semgrep failure undiagnosable:
    no stdout, no stderr, and a JSONDecodeError from parse_output
    standing in for a cause. The exit code is the only thing that
    separates an OOM kill from a tool that merely wrote garbage.
    """
    killed = subprocess.CompletedProcess(args=["semgrep"], returncode=-9, stdout="", stderr="")

    status = _exit_status(killed)

    assert "exit=-9" in status
    assert "SIGKILL" in status
    assert "stdout_len=0" in status


def test_exit_status_distinguishes_wrote_nothing_from_wrote_garbage():
    wrote_garbage = subprocess.CompletedProcess(args=["semgrep"], returncode=2, stdout="not json", stderr="")

    status = _exit_status(wrote_garbage)

    assert "exit=2" in status
    assert "stdout_len=8" in status


def test_exit_status_never_logs_stdout_content():
    """Tool stdout carries matched source lines, so only its length is
    ever recorded.
    """
    secret = "SECRET_TOKEN_VALUE_DO_NOT_LOG"
    proc = subprocess.CompletedProcess(args=["semgrep"], returncode=1, stdout=secret, stderr="")

    status = _exit_status(proc)

    assert secret not in status
    assert f"stdout_len={len(secret)}" in status


def test_exit_status_when_the_subprocess_never_produced_a_result():
    status = _exit_status(None)

    assert "no subprocess result" in status


def test_the_failure_log_carries_exit_code_and_stderr(caplog):
    """End to end through run_tool_on_pr: a tool that exits non-zero and
    writes unparseable stdout must leave both its exit code and its own
    stderr in the log.
    """
    def build_cmd(tmp_dir):
        return [sys.executable, "-c", "import sys; sys.stderr.write('real cause here'); sys.exit(3)"]

    def parse_output(stdout, tmp_dir):
        raise json.JSONDecodeError("Expecting value", "", 0)

    with caplog.at_level(logging.ERROR):
        findings = run_tool_on_pr("semgrep", build_cmd, parse_output, {"a.py": "x = 1\n"}, timeout=30)

    assert len(findings) == 1 and findings[0].rule_id == UNAVAILABLE_RULE_ID
    logged = caplog.text
    assert "exit=3" in logged
    assert "real cause here" in logged
