"""Regression coverage for codeguard.worker.main._check_run_conclusion
— a pure function, no DB/API access needed. It decides the Check Run's
conclusion and title only; the summary body it used to build now lives
in codeguard/github/check_summary.py (tests/github/test_check_summary.py).
"""

from __future__ import annotations

from codeguard.severity import Severity
from codeguard.worker.main import _check_run_conclusion
from tests.pipeline.conftest import make_finding


def test_no_findings_above_gate_threshold_succeeds():
    findings = [make_finding(severity=Severity.MEDIUM)]

    conclusion, title, blocking = _check_run_conclusion(findings, Severity.CRITICAL)

    assert conclusion == "success"
    assert "No blocking findings" in title
    assert blocking == []


def test_a_finding_at_gate_threshold_fails():
    findings = [make_finding(severity=Severity.CRITICAL, rule_id="B608", message="sqli")]

    conclusion, title, blocking = _check_run_conclusion(findings, Severity.CRITICAL)

    assert conclusion == "failure"
    assert "1 finding(s) at or above CRITICAL" in title
    assert [f.rule_id for f in blocking] == ["B608"]


def test_a_finding_above_gate_threshold_fails():
    findings = [make_finding(severity=Severity.CRITICAL)]

    conclusion, _, _ = _check_run_conclusion(findings, Severity.HIGH)

    assert conclusion == "failure"


def test_a_finding_below_gate_threshold_succeeds():
    findings = [make_finding(severity=Severity.HIGH)]

    conclusion, _, _ = _check_run_conclusion(findings, Severity.CRITICAL)

    assert conclusion == "success"


def test_every_blocking_finding_is_returned_for_the_summary_to_render():
    """The blocking list is handed to github/check_summary.py, which
    picks the worst itself -- so this returns all of them, not just the
    worst, and the title counts them.
    """
    low_blocking = make_finding(severity=Severity.HIGH, rule_id="R1", message="minor")
    worst = make_finding(severity=Severity.CRITICAL, rule_id="R2", message="severe")

    _, title, blocking = _check_run_conclusion([low_blocking, worst], Severity.HIGH)

    assert sorted(f.rule_id for f in blocking) == ["R1", "R2"]
    assert "2 finding(s) at or above HIGH" in title
