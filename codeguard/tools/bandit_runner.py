from __future__ import annotations

import json

from codeguard.severity import Severity
from codeguard.tools.base import resolve_tool_command, run_tool_on_file
from codeguard.tools.models import Finding

TOOL_NAME = "bandit"
DEFAULT_TIMEOUT = 30

_SEVERITY_MAP = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def _build_cmd(tmp_path: str) -> list[str]:
    return resolve_tool_command(TOOL_NAME) + ["-f", "json", "-q", tmp_path]


def _parse(stdout: str, file_path: str) -> list[Finding]:
    data = json.loads(stdout)
    findings = []
    for r in data.get("results", []):
        severity = _SEVERITY_MAP.get(r.get("issue_severity", "LOW"), Severity.LOW)
        line = r.get("line_number", 0)
        line_range = r.get("line_range") or [line]
        findings.append(Finding.create(
            file=file_path, start_line=line, end_line=line_range[-1], severity=severity,
            source_tool=TOOL_NAME, rule_id=r.get("test_id", "unknown"),
            message=(r.get("issue_text") or "").strip(),
        ))
    return findings


def run_bandit(file_path: str, content: str, timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    return run_tool_on_file(TOOL_NAME, _build_cmd, _parse, file_path, content, timeout)
