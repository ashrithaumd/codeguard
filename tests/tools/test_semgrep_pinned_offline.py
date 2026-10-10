"""Semgrep is pinned at 1.95.0 and never reaches the network.

1.95.0 is the newest release that still emits the data-flow traces the
taint flow note reads ("Assigned at line 44, sent to the model at line 49");
later ones drop them, which the free scanner-only gate caught
(docs/backlog.md). It is also the first that runs the vendored Java and C#
rules in full: on 1.45.0 five Java rules never fired.

`--metrics=off` stops metrics but NOT Semgrep's own new-version check,
which is a separate network call on every run. SEMGREP_ENABLE_VERSION_CHECK=0
stops that, set both in the image and by the runner itself, so a process
that lost the image's environment still does not call out.
scripts/smoke_image.sh proves no connection is attempted with the network
removed.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from unittest.mock import patch

from codeguard.tools import semgrep_runner

ROOT = Path(__file__).resolve().parents[2]


def _captured_run():
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout='{"results": [], "errors": []}', stderr="")
    return calls, fake_run


def test_the_runner_turns_off_the_version_check_and_metrics_in_its_own_environment():
    calls, fake = _captured_run()
    with patch("codeguard.tools.base.subprocess.run", side_effect=fake):
        semgrep_runner.run_semgrep({"a.py": "x = 1\n"})
    [(cmd, kwargs)] = calls
    env = kwargs["env"]
    assert env["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert env["SEMGREP_SEND_METRICS"] == "off"
    assert "--metrics=off" in cmd and "--dataflow-traces" in cmd


def test_the_python_scan_still_uses_only_our_own_rules():
    """Vendored packs live outside rules/ and are not loaded by this runner
    until a later item activates them for other languages."""
    calls, fake = _captured_run()
    with patch("codeguard.tools.base.subprocess.run", side_effect=fake):
        semgrep_runner.run_semgrep({"a.py": "x = 1\n"})
    configs = [a for a in calls[0][0] if a.startswith("--config=")]
    assert configs == [f"--config={ROOT / 'rules'}"]


def test_other_tools_keep_their_inherited_environment():
    from codeguard.tools import bandit_runner
    calls, fake = _captured_run()
    with patch("codeguard.tools.base.subprocess.run", side_effect=fake):
        bandit_runner.run_bandit({"a.py": "x = 1\n"})
    assert calls[0][1].get("env") is None


def test_semgrep_is_pinned_to_1_95_0_with_setuptools_below_81():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"ARG SEMGREP_VERSION=1\.95\.0\n", dockerfile)
    assert '"semgrep==${SEMGREP_VERSION}"' in dockerfile
    pin = re.search(r'"setuptools==(\d+)\.(\d+)\.(\d+)"', dockerfile)
    assert pin and int(pin.group(1)) < 81


def test_the_image_disables_the_version_check_too():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"SEMGREP_ENABLE_VERSION_CHECK=0", dockerfile)
    assert re.search(r"SEMGREP_SEND_METRICS=off", dockerfile)


# --------------------------------------------------------------------------
# An explicit binary, and a version check at runtime
# --------------------------------------------------------------------------
#
# Semgrep lives in its own environment in the image (/opt/semgrep: its
# OpenTelemetry pin cannot coexist with the app's), and the runner calls it
# by SEMGREP_BIN, never by a PATH lookup that could find another semgrep.
# Outside Docker, with SEMGREP_BIN unset, it falls back to PATH. A version
# other than 1.95.0 does not stop a review or an audit; it is said, in the
# same warning that says a tool did not run.



def test_the_runner_uses_semgrep_bin_when_it_is_set(monkeypatch):
    monkeypatch.setenv("SEMGREP_BIN", "/opt/semgrep/bin/semgrep")
    assert semgrep_runner.semgrep_command() == ["/opt/semgrep/bin/semgrep"]
    calls, fake = _captured_run()
    with patch("codeguard.tools.base.subprocess.run", side_effect=fake):
        semgrep_runner.run_semgrep({"a.py": "x = 1\n"})
    assert calls[0][0][0] == "/opt/semgrep/bin/semgrep"


def test_outside_docker_it_falls_back_to_path(monkeypatch):
    monkeypatch.delenv("SEMGREP_BIN", raising=False)
    with patch("codeguard.tools.semgrep_runner.resolve_tool_command", return_value=["semgrep"]):
        assert semgrep_runner.semgrep_command() == ["semgrep"]


def _version_output(text, returncode=0):
    return subprocess.CompletedProcess(["semgrep", "--version"], returncode, stdout=text, stderr="")


def test_the_expected_version_means_no_warning():
    semgrep_runner.version_warning.cache_clear()
    with patch("codeguard.tools.semgrep_runner.subprocess.run", return_value=_version_output("1.95.0\n")):
        assert semgrep_runner.version_warning() is None


def test_another_version_is_said_in_the_exact_words():
    semgrep_runner.version_warning.cache_clear()
    with patch("codeguard.tools.semgrep_runner.subprocess.run", return_value=_version_output("1.94.0\n")):
        assert semgrep_runner.version_warning() == "Semgrep version mismatch (found 1.94.0, expected 1.95.0)"


def test_a_missing_semgrep_is_left_to_the_did_not_run_warning():
    semgrep_runner.version_warning.cache_clear()
    with patch("codeguard.tools.semgrep_runner.subprocess.run", side_effect=FileNotFoundError("semgrep")):
        assert semgrep_runner.version_warning() is None
    semgrep_runner.version_warning.cache_clear()


def test_the_image_installs_semgrep_in_its_own_environment_and_points_the_runner_at_it():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "python -m venv /opt/semgrep" in dockerfile
    assert re.search(r'setuptools==80\.10\.2', dockerfile)
    assert re.search(r"SEMGREP_BIN=/opt/semgrep/bin/semgrep", dockerfile)


def test_the_app_dependencies_do_not_carry_semgrep():
    """Its OpenTelemetry pin (~=1.25) cannot coexist with mcp's (>=1.28)."""
    assert '"semgrep==' not in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_a_mismatch_reaches_the_audits_incompleteness_warning():
    from codeguard.cli import build_report_data
    data = build_report_data(
        target="t", files_scanned=1, files_ai_aware=0, ai_reviewed_findings=[], passthrough_findings=[],
        dismissed=[], eval_hygiene_findings=[], osv_findings=[], skipped_files=[], verdict_call_failures=[],
        unavailable_tools=[], tokens_in=0, tokens_out=0, estimated_cost_usd=0.0, elapsed_s=1.0,
        tool_warnings=["Semgrep version mismatch (found 1.94.0, expected 1.95.0)"])
    assert "Semgrep version mismatch (found 1.94.0, expected 1.95.0)" in data["incomplete"]


def _check_summary(**over):
    from codeguard.github.check_summary import render_check_summary
    from codeguard.severity import Severity
    kw = dict(findings=[], tool_findings=[], blocking=[], gate_threshold=Severity.CRITICAL, files_seen=1,
              files_reviewed=1, budget_exceeded=False, fix_suggestion_count=0, dismissed_count=0,
              tokens_in=0, tokens_out=0, estimated_cost_usd=0.0, duration_s=1.0)
    kw.update(over)
    return render_check_summary(**kw)


def test_a_mismatch_reaches_the_pr_check_summary_and_nothing_changes_without_one():
    with_warning = _check_summary(tool_warnings=["Semgrep version mismatch (found 1.94.0, expected 1.95.0)"])
    assert "Semgrep version mismatch (found 1.94.0, expected 1.95.0)" in with_warning
    assert _check_summary() == _check_summary(tool_warnings=[])


def test_semgreps_own_directory_comes_first_on_path(monkeypatch):
    """Its front end launches `pysemgrep` by PATH lookup: it must be the one
    from the same isolated install."""
    monkeypatch.setenv("SEMGREP_BIN", "/opt/semgrep/bin/semgrep")
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    env = semgrep_runner.semgrep_env()
    assert env["PATH"].split(":")[0] == "/opt/semgrep/bin"
    assert env["SEMGREP_ENABLE_VERSION_CHECK"] == "0" and env["SEMGREP_SEND_METRICS"] == "off"
