from __future__ import annotations

import json
from pathlib import Path

from codeguard.severity import Severity
from codeguard.tools.base import resolve_original_path, resolve_tool_command, run_tool_on_pr
from codeguard.tools.models import Finding

TOOL_NAME = "semgrep"
DEFAULT_TIMEOUT = 60

_SEVERITY_MAP = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}

# Custom rulesets only, per the Phase 4.1 decision — Bandit owns generic
# Python security. Phase 6 populates this directory with the real
# AI-aware ruleset (rules/llm-security.yaml); see rules/placeholder.yaml
# for why the two registry packs tried in Phase 4 were dropped.
RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"


def _build_cmd(tmp_dir: str) -> list[str]:
    return resolve_tool_command(TOOL_NAME) + [f"--config={RULES_DIR}", "--json", "--quiet", "--metrics=off", tmp_dir]


def _parse(stdout: str, tmp_dir: str) -> list[Finding]:
    data = json.loads(stdout)
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        severity = _SEVERITY_MAP.get(extra.get("severity", "INFO"), Severity.LOW)
        start = r.get("start", {}).get("line", 0)
        end = r.get("end", {}).get("line", start)
        findings.append(Finding.create(
            file=resolve_original_path(tmp_dir, r.get("path", "")),
            start_line=start, end_line=end, severity=severity,
            source_tool=TOOL_NAME, rule_id=r.get("check_id", "unknown"),
            message=(extra.get("message") or "").strip(),
        ))
    return findings


def run_semgrep(files: dict[str, str], timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    return run_tool_on_pr(TOOL_NAME, _build_cmd, _parse, files, timeout)
