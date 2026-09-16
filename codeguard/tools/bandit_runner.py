from __future__ import annotations

import json

from codeguard.severity import Severity
from codeguard.tools.base import resolve_original_path, resolve_tool_command, run_tool_on_pr
from codeguard.tools.models import Finding

TOOL_NAME = "bandit"
DEFAULT_TIMEOUT = 30

_SEVERITY_MAP = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def _build_cmd(tmp_dir: str) -> list[str]:
    return resolve_tool_command(TOOL_NAME) + ["-f", "json", "-q", "-r", tmp_dir]


def _parse(stdout: str, tmp_dir: str) -> list[Finding]:
    data = json.loads(stdout)
    findings = []
    for r in data.get("results", []):
        severity = _SEVERITY_MAP.get(r.get("issue_severity", "LOW"), Severity.LOW)
        line = r.get("line_number", 0)
        line_range = r.get("line_range") or [line]
        findings.append(Finding.create(
            file=resolve_original_path(tmp_dir, r.get("filename", "")),
            start_line=line, end_line=line_range[-1], severity=severity,
            source_tool=TOOL_NAME, rule_id=r.get("test_id", "unknown"),
            message=(r.get("issue_text") or "").strip(),
        ))
    return findings


def run_bandit(files: dict[str, str], timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    return run_tool_on_pr(TOOL_NAME, _build_cmd, _parse, files, timeout)
