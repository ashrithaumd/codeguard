from codeguard.severity import Severity
from codeguard.tools.line_filter import filter_findings_to_changed_lines
from codeguard.tools.models import Finding


def _finding(file, line):
    return Finding.create(file=file, start_line=line, end_line=line, severity=Severity.LOW,
                           source_tool="ruff", rule_id="X", message="m")


def test_finding_within_changed_range_is_kept():
    findings = [_finding("a.py", 10)]
    ranges = {"a.py": [(8, 5)]}  # covers lines 8-12
    assert filter_findings_to_changed_lines(findings, ranges) == findings


def test_finding_far_outside_changed_range_is_dropped():
    findings = [_finding("a.py", 100)]
    ranges = {"a.py": [(8, 5)]}
    assert filter_findings_to_changed_lines(findings, ranges) == []


def test_finding_just_outside_range_within_context_margin_is_kept():
    # range covers 8-12; LINE_CONTEXT=3 extends the window to 15
    findings = [_finding("a.py", 14)]
    ranges = {"a.py": [(8, 5)]}
    assert filter_findings_to_changed_lines(findings, ranges) == findings


def test_finding_in_untouched_file_is_dropped():
    findings = [_finding("b.py", 10)]
    ranges = {"a.py": [(8, 5)]}
    assert filter_findings_to_changed_lines(findings, ranges) == []


def test_tool_unavailable_meta_finding_always_kept_regardless_of_line():
    unavailable = Finding.create(file="a.py", start_line=0, end_line=0, severity=Severity.LOW,
                                  source_tool="semgrep", rule_id="internal.tool_unavailable", message="timed out")
    assert filter_findings_to_changed_lines([unavailable], {}) == [unavailable]
