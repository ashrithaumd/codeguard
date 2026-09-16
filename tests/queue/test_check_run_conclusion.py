"""Regression coverage for codeguard.worker.main._check_run_conclusion
— a pure function, no DB/API access needed."""

from __future__ import annotations

from codeguard.severity import Severity
from codeguard.worker.main import _check_run_conclusion
from tests.pipeline.conftest import make_finding


def test_no_findings_above_gate_threshold_succeeds():
    findings = [make_finding(severity=Severity.MEDIUM)]

    conclusion, title, summary = _check_run_conclusion(findings, Severity.CRITICAL)

    assert conclusion == "success"
    assert "No blocking findings" in title


def test_a_finding_at_gate_threshold_fails():
    findings = [make_finding(severity=Severity.CRITICAL, rule_id="B608", message="sqli")]

    conclusion, title, summary = _check_run_conclusion(findings, Severity.CRITICAL)

    assert conclusion == "failure"
    assert "B608" in summary


def test_a_finding_above_gate_threshold_fails():
    findings = [make_finding(severity=Severity.CRITICAL)]

    conclusion, _, _ = _check_run_conclusion(findings, Severity.HIGH)

    assert conclusion == "failure"


def test_a_finding_below_gate_threshold_succeeds():
    findings = [make_finding(severity=Severity.HIGH)]

    conclusion, _, _ = _check_run_conclusion(findings, Severity.CRITICAL)

    assert conclusion == "success"


def test_worst_of_multiple_blocking_findings_is_reported():
    low_blocking = make_finding(severity=Severity.HIGH, rule_id="R1", message="minor")
    worst = make_finding(severity=Severity.CRITICAL, rule_id="R2", message="severe")

    _, _, summary = _check_run_conclusion([low_blocking, worst], Severity.HIGH)

    assert "R2" in summary
    assert "2 confirmed finding(s)" in summary
