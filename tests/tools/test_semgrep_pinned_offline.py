"""Semgrep stays at 1.45.0 and never reaches the network.

Pinned, not upgraded: releases after ~1.95 stop emitting the data-flow
traces the taint flow note reads ("Assigned at line 44, sent to the model
at line 49"), which the free scanner-only gate caught (docs/backlog.md).

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


def test_semgrep_is_pinned_to_1_45_0():
    assert re.search(r'"semgrep==1\.45\.0"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_image_disables_the_version_check_too():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"SEMGREP_ENABLE_VERSION_CHECK=0", dockerfile)
    assert re.search(r"SEMGREP_SEND_METRICS=off", dockerfile)
