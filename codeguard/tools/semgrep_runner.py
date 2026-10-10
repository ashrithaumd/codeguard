from __future__ import annotations

import json
import os
import subprocess
from functools import lru_cache
from pathlib import Path

from codeguard.severity import Severity
from codeguard.tools.base import resolve_original_path, resolve_tool_command, run_tool_on_pr
from codeguard.tools.models import Finding

TOOL_NAME = "semgrep"
DEFAULT_TIMEOUT = 60

_SEVERITY_MAP = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}

# Custom rulesets only — Bandit owns generic Python security. This
# directory holds the real AI-aware ruleset (rules/llm-security.yaml,
# 10 rules covering
# prompt-injection concatenation, missing system/user separation,
# LLM-output-to-dangerous-sink/SQL taint, missing max_tokens/timeout,
# sync calls in async handlers, unpinned model aliases, hardcoded API
# keys, and logging full prompts/responses).
RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"


EXPECTED_VERSION = "1.95.0"


def semgrep_command() -> list[str]:
    """The Semgrep to run: SEMGREP_BIN when set (the image sets it to its own
    /opt/semgrep environment), never a PATH lookup that could find another
    semgrep; outside Docker, with it unset, the usual resolution."""
    explicit = os.environ.get("SEMGREP_BIN")
    return [explicit] if explicit else resolve_tool_command(TOOL_NAME)


def semgrep_env() -> dict[str, str]:
    """The environment every Semgrep call runs with: offline (no version
    check, no metrics), and -- when SEMGREP_BIN is set -- that binary's own
    directory FIRST on PATH, because Semgrep's front end launches its
    companion `pysemgrep` by PATH lookup and it must be the one from the same
    install, never another found elsewhere on the system."""
    env = {**os.environ, **_OFFLINE_ENV}
    explicit = os.environ.get("SEMGREP_BIN")
    if explicit:
        env["PATH"] = os.pathsep.join([os.path.dirname(explicit), env.get("PATH", "")])
    return env


@lru_cache(maxsize=1)
def version_warning() -> str | None:
    """"Semgrep version mismatch (found X, expected 1.95.0)", or None. Checked
    once per process. A mismatch does not stop a review or an audit; it is
    said in the same warning that says a tool did not run. A missing semgrep
    is None here: the did-not-run warning already covers it."""
    try:
        proc = subprocess.run(semgrep_command() + ["--version"], capture_output=True, text=True, timeout=30,
                              env=semgrep_env())
    except (OSError, subprocess.SubprocessError):
        return None
    lines = proc.stdout.strip().splitlines()
    found = lines[-1].strip() if lines else ""
    if proc.returncode != 0 or not found or found == EXPECTED_VERSION:
        return None
    return f"Semgrep version mismatch (found {found}, expected {EXPECTED_VERSION})"


def _build_cmd(tmp_dir: str) -> list[str]:
    return semgrep_command() + [
        f"--config={RULES_DIR}", "--json", "--quiet", "--metrics=off",
        # Where a taint rule's value came from, not just where it ended up:
        # an injection finding names the line the prompt was built on.
        "--dataflow-traces",
        tmp_dir,
    ]


def _parse(stdout: str, tmp_dir: str) -> list[Finding]:
    data = json.loads(stdout)
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        severity = _SEVERITY_MAP.get(extra.get("severity", "INFO"), Severity.LOW)
        start = r.get("start", {}).get("line", 0)
        end = r.get("end", {}).get("line", start)
        finding = Finding.create(
            file=resolve_original_path(tmp_dir, r.get("path", "")),
            start_line=start, end_line=end, severity=severity,
            source_tool=TOOL_NAME, rule_id=r.get("check_id", "unknown"),
            message=(extra.get("message") or "").strip(),
        )
        source_line = _taint_source_line(extra)
        if source_line and source_line != start:
            finding = finding.model_copy(update={"source_line": source_line})
        findings.append(finding)
    return findings


def _taint_source_line(extra: dict) -> int:
    """The line a taint rule's source sits on, from --dataflow-traces:
    `taint_source` is ["CliLoc", [location, text]]. 0 for a search-mode
    rule, or any shape this does not recognise -- a missing trace must
    never cost the finding itself."""
    try:
        return int(extra["dataflow_trace"]["taint_source"][1][0]["start"]["line"])
    except (KeyError, IndexError, TypeError, ValueError):
        return 0


# Pinned at 1.95.0 (pyproject.toml): later releases drop the data-flow
# traces the flow note reads. --metrics=off does not stop Semgrep's own
# new-version check, a separate network call on every run; this does, and
# it is set here as well as in the image so it holds wherever this runs.
_OFFLINE_ENV = {"SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}


def run_semgrep(files: dict[str, str], timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    return run_tool_on_pr(TOOL_NAME, _build_cmd, _parse, files, timeout, env=semgrep_env())
