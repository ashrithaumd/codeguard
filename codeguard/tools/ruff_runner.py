from __future__ import annotations

import json

from codeguard.severity import Severity
from codeguard.tools.base import resolve_tool_command, run_tool_on_file
from codeguard.tools.models import Finding

TOOL_NAME = "ruff"
DEFAULT_TIMEOUT = 20


def _build_cmd(tmp_path: str) -> list[str]:
    return resolve_tool_command(TOOL_NAME) + ["check", "--output-format=json", "--exit-zero", tmp_path]


def _severity_for(code: str) -> Severity:
    # Ruff itself has no severity concept. "S"-prefixed codes are its
    # bundled flake8-bandit port (security-relevant) — treated as
    # MEDIUM; everything else is an ordinary style/correctness lint,
    # LOW relative to a real security finding from bandit/semgrep.
    return Severity.MEDIUM if code.startswith("S") else Severity.LOW


def _parse(stdout: str, file_path: str) -> list[Finding]:
    data = json.loads(stdout)
    findings = []
    for r in data:
        code = r.get("code") or "unknown"
        loc = r.get("location") or {}
        end_loc = r.get("end_location") or loc
        start_line = loc.get("row", 0)
        findings.append(Finding.create(
            file=file_path, start_line=start_line, end_line=end_loc.get("row", start_line),
            severity=_severity_for(code), source_tool=TOOL_NAME, rule_id=code,
            message=(r.get("message") or "").strip(),
        ))
    return findings


def run_ruff(file_path: str, content: str, timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    return run_tool_on_file(TOOL_NAME, _build_cmd, _parse, file_path, content, timeout)
