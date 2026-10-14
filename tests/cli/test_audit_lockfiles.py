"""Audits: every npm/yarn/pnpm, Go, Maven/Gradle and NuGet lockfile in the
repository goes to OSV-Scanner, and everything it reports is listed with
the dependency findings. Python's check is unchanged and a Python-only
repository never runs OSV-Scanner."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from codeguard.cli import run_audit
from codeguard.severity import Severity
from codeguard.tools.models import Finding
from codeguard.tools.osv_runner import DependencyCheck

LOCK = '{"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.15"}}}\n'


def _osv_finding():
    return Finding.create(file="web/package-lock.json", start_line=1, end_line=1, severity=Severity.MEDIUM,
                          source_tool="osv", rule_id="GHSA-29mw-wpgm-hmr9",
                          message="lodash@4.17.15 has a known vulnerability (GHSA-29mw-wpgm-hmr9): ReDoS in lodash")


def _run(tmp_path, scan_result):
    output = tmp_path / "out" / "report.md"
    output.parent.mkdir()
    with patch("codeguard.cli.check_dependency_updates_status", return_value=DependencyCheck([])), \
         patch("codeguard.cli.review_security_generic", side_effect=lambda s: {"findings": [], "dismissed_findings": []}), \
         patch("codeguard.cli.scan_lockfiles", return_value=scan_result) as scan:
        exit_code, error = run_audit(str(tmp_path / "repo"), str(output), post_issue_flag=False)
    return exit_code, error, output.read_text(encoding="utf-8") if output.exists() else "", scan


def _repo(tmp_path):
    root = tmp_path / "repo"
    (root / "web" / "node_modules" / "x").mkdir(parents=True)
    (root / "web" / "index.js").write_text("console.log(1);\n")
    (root / "web" / "package-lock.json").write_text(LOCK)
    (root / "web" / "node_modules" / "x" / "package-lock.json").write_text(LOCK)
    (root / "go.mod").write_text("module x\n\nrequire github.com/gin-gonic/gin v1.6.0\n")
    (root / "poetry.lock").write_text("[[package]]\n")
    return root


def test_every_lockfile_is_scanned_and_its_findings_reported(tmp_path):
    _repo(tmp_path)
    exit_code, error, report, scan = _run(tmp_path, DependencyCheck([_osv_finding()]))
    assert (exit_code, error) == (0, None)
    assert sorted(scan.call_args.args[0]) == ["go.mod", "web/package-lock.json"]
    assert scan.call_args.args[0]["web/package-lock.json"] == LOCK
    assert "GHSA-29mw-wpgm-hmr9" in report and "web/package-lock.json" in report


def test_osv_unreachable_is_said(tmp_path):
    _repo(tmp_path)
    _, _, report, _ = _run(tmp_path, DependencyCheck([], unavailable=True))
    assert "Dependency CVE check unavailable" in report


@pytest.mark.skipif(not hasattr(os, "symlink") or os.name == "nt", reason="symlinks")
def test_a_symlinked_lockfile_is_not_read(tmp_path):
    _repo(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_text("SECRET")
    os.symlink(secret, tmp_path / "repo" / "yarn.lock")
    _, _, _, scan = _run(tmp_path, DependencyCheck([]))
    assert "yarn.lock" not in scan.call_args.args[0]


def test_a_python_only_audit_never_runs_osv_scanner(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    (root / "requirements.txt").write_text("pyyaml==5.3\n")
    (root / "poetry.lock").write_text("[[package]]\n")
    with patch("codeguard.cli.review_security", side_effect=lambda s: {"findings": [], "dismissed_findings": []}), \
         patch("codeguard.cli.review_ai_aware", side_effect=lambda s: {"findings": [], "dismissed_findings": []}):
        _, _, _, scan = _run(tmp_path, DependencyCheck([]))
    # No lockfile is handed over, and with none OSV-Scanner is never started
    # (test_osv_scanner_runner.test_nothing_to_scan_runs_nothing).
    scan.assert_called_once_with({})
