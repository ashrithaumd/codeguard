"""zizmor over GitHub Actions workflows: pinned, offline, parsed to Findings.

The parse tests use the JSON shape zizmor 1.30.1 really emits (recorded
from a run); the live tests run the pinned binary the image installs in its
own environment (/opt/zizmor, ZIZMOR_BIN), and skip only where it is absent.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from codeguard.severity import Severity
from codeguard.tools.zizmor_runner import (
    EXPECTED_VERSION,
    TOOL_NAME,
    _build_cmd,
    _parse,
    run_zizmor,
    zizmor_env,
)

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ".github/workflows/ci.yml"
INJECTION = (
    "name: ci\non:\n  issues:\n    types: [opened]\njobs:\n  greet:\n    runs-on: ubuntu-latest\n"
    "    permissions: {}\n    steps:\n"
    '      - run: echo "${{ github.event.issue.title }}"\n'
)


def _loc(kind, path, row, annotation="a", feature="f"):
    return {"symbolic": {"key": {"Local": {"verbatim_path": path}}, "annotation": annotation, "kind": kind},
            "concrete": {"location": {"start_point": {"row": row, "column": 0}, "end_point": {"row": row, "column": 5}},
                         "feature": feature}}


def _result(ident, severity, confidence, locations, desc="d", ignored=False):
    return {"ident": ident, "desc": desc, "url": f"https://docs.zizmor.sh/audits/#{ident}", "ignored": ignored,
            "determinations": {"severity": severity, "confidence": confidence, "persona": "Regular"},
            "locations": locations}


def test_the_primary_location_is_the_finding_one_based_at_its_original_path(tmp_path):
    tmp = str(tmp_path)
    path = f"{tmp}/.github/workflows/ci.yml"
    out = json.dumps([_result("template-injection", "High", "High", [
        _loc("Hidden", path, 12, "this step"),
        _loc("Primary", path, 12, "may expand into attacker-controllable code"),
        _loc("Related", path, 3, "this run block"),
    ], desc="code injection via template expansion")])
    [f] = _parse(out, tmp)
    assert (f.file, f.start_line, f.rule_id, f.source_tool, f.severity) == (
        WORKFLOW, 13, "template-injection", "zizmor", Severity.HIGH)
    assert "code injection via template expansion" in f.message
    assert "may expand into attacker-controllable code" in f.message


def test_severity_maps_and_ignored_results_are_dropped(tmp_path):
    tmp = str(tmp_path)
    path = f"{tmp}/.github/workflows/ci.yml"
    out = json.dumps([
        _result("excessive-permissions", "Medium", "Medium", [_loc("Primary", path, 1)]),
        _result("artipacked", "Low", "Low", [_loc("Primary", path, 2)]),
        _result("unpinned-uses", "High", "High", [_loc("Primary", path, 3)], ignored=True),
    ])
    assert [(f.rule_id, f.severity) for f in _parse(out, tmp)] == [
        ("excessive-permissions", Severity.MEDIUM), ("artipacked", Severity.LOW)]


def test_the_command_is_offline_without_config_and_never_gates_on_exit_codes():
    cmd = _build_cmd("/tmp/x")
    for flag in ("--offline", "--no-config", "--no-exit-codes", "--no-progress"):
        assert flag in cmd
    assert cmd[cmd.index("--format") + 1] == "json"
    assert cmd[-1] == "/tmp/x"


def test_no_github_token_ever_reaches_zizmor():
    with patch.dict(os.environ, {"GH_TOKEN": "x", "GITHUB_TOKEN": "y", "ZIZMOR_GITHUB_TOKEN": "z"}):
        env = zizmor_env()
    assert not {"GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN"} & set(env)
    assert env["ZIZMOR_OFFLINE"] == "true"


def test_only_workflow_files_are_handed_over():
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="[]", stderr="")

    with patch("codeguard.tools.base.subprocess.run", side_effect=fake_run):
        assert run_zizmor({"app.py": "x\n", "Dockerfile": "FROM a\n", "k8s/x.yaml": "a: 1\n"}) == []
    assert calls == []


def test_a_failed_run_is_named_for_the_did_not_run_warning():
    from codeguard.tools.base import UNAVAILABLE_RULE_ID
    with patch("codeguard.tools.base.subprocess.run", side_effect=subprocess.TimeoutExpired("zizmor", 60)):
        [f] = run_zizmor({WORKFLOW: INJECTION})
    assert (f.rule_id, f.source_tool) == (UNAVAILABLE_RULE_ID, TOOL_NAME)


def test_the_image_pins_zizmor_by_hash_in_its_own_environment():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "python -m venv /opt/zizmor" in dockerfile
    assert f"ARG ZIZMOR_VERSION={EXPECTED_VERSION}\n" in dockerfile
    assert re.search(r"ARG ZIZMOR_SHA256=[0-9a-f]{64}\n", dockerfile)
    assert '"zizmor==${ZIZMOR_VERSION} --hash=sha256:${ZIZMOR_SHA256}"' in dockerfile
    assert "--require-hashes" in dockerfile
    assert "ZIZMOR_BIN=/opt/zizmor/bin/zizmor" in dockerfile
    assert '"zizmor' not in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


_LIVE = pytest.mark.skipif(not os.environ.get("ZIZMOR_BIN"), reason="the pinned zizmor is installed in the image only")


@_LIVE
def test_the_pinned_version_runs():
    out = subprocess.run([os.environ["ZIZMOR_BIN"], "--version"], capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == f"zizmor {EXPECTED_VERSION}"


@_LIVE
def test_template_injection_in_a_real_workflow_is_found_at_its_line():
    findings = run_zizmor({WORKFLOW: INJECTION})
    hits = [(f.file, f.start_line) for f in findings if f.rule_id == "template-injection"]
    assert hits == [(WORKFLOW, 10)]


@_LIVE
def test_a_malformed_workflow_beside_a_good_one_does_not_stop_the_scan():
    findings = run_zizmor({WORKFLOW: INJECTION, ".github/workflows/broken.yml": "on: [push\njobs: : :\n"})
    assert any(f.rule_id == "template-injection" for f in findings)
