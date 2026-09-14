"""Shared Finding construction helper for pipeline tests — same pattern
as Phase 4's tests/tools/test_models.py and test_line_filter.py
(Finding.create with sensible defaults), centralized here so pipeline
tests don't each reinvent it.
"""

from __future__ import annotations

from codeguard.severity import Severity
from codeguard.tools.models import Finding


def make_finding(
    file: str = "a.py",
    line: int = 1,
    severity: Severity = Severity.MEDIUM,
    tool: str = "bandit",
    rule_id: str = "B000",
    message: str = "issue",
) -> Finding:
    return Finding.create(
        file=file, start_line=line, end_line=line, severity=severity,
        source_tool=tool, rule_id=rule_id, message=message,
    )
