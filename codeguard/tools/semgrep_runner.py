from __future__ import annotations

import json

from codeguard.severity import Severity
from codeguard.tools.base import resolve_tool_command, run_tool_on_file
from codeguard.tools.models import Finding

TOOL_NAME = "semgrep"
DEFAULT_TIMEOUT = 60

_SEVERITY_MAP = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


def _build_cmd(tmp_path: str) -> list[str]:
    # p/security-audit: a pre-packaged, general-purpose security ruleset
    # (SQL injection, hardcoded secrets, etc.) — not the project's own
    # rules/llm-security.yaml, which is Phase 6's AI-aware agent, not
    # this generic deterministic layer.
    return resolve_tool_command(TOOL_NAME) + ["--config=p/security-audit", "--json", "--quiet", "--metrics=off", tmp_path]


def _parse(stdout: str, file_path: str) -> list[Finding]:
    data = json.loads(stdout)
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        severity = _SEVERITY_MAP.get(extra.get("severity", "INFO"), Severity.LOW)
        start = r.get("start", {}).get("line", 0)
        end = r.get("end", {}).get("line", start)
        findings.append(Finding.create(
            file=file_path, start_line=start, end_line=end, severity=severity,
            source_tool=TOOL_NAME, rule_id=r.get("check_id", "unknown"),
            message=(extra.get("message") or "").strip(),
        ))
    return findings


def run_semgrep(file_path: str, content: str, timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    return run_tool_on_file(TOOL_NAME, _build_cmd, _parse, file_path, content, timeout)
