"""Shared execution harness for all three tool runners: writes file
content to a temp file (these are CLI tools operating on files, not
libraries taking a string), runs the tool under a timeout, and hands
stdout to a tool-specific parser. A crash or timeout NEVER aborts the
review — it produces a single "tool unavailable" Finding and increments
a failure counter, same as any other tool output would be handled.

Deliberately does NOT check the subprocess's exit code: Semgrep, Bandit,
and Ruff all conventionally exit non-zero when they *find issues* — that
is their normal, successful behavior, not a failure. Only a real
execution problem (timeout, the binary missing, unparseable output)
counts as "tool unavailable" here.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

from codeguard.severity import Severity
from codeguard.tools.metrics import tool_failures_total, tool_run_duration_seconds
from codeguard.tools.models import Finding

logger = logging.getLogger(__name__)


def resolve_tool_command(name: str) -> list[str]:
    """Command prefix to invoke this tool — usually just [path-to-exe].

    Prefers the exact binary installed alongside this interpreter
    (sys.exec_prefix reliably points at the venv root regardless of
    whether it's "activated") over a bare name + PATH lookup. Without
    this, subprocess.run(["bandit", ...]) fails on Windows with
    WinError 2 whenever the venv's Scripts/ isn't on PATH — which it
    isn't unless something ran activate.bat/Activate.ps1 first, and
    nothing here does.

    Bandit and Ruff both ship a real compiled .exe wrapper on Windows;
    Semgrep's own entry point does not — it's a Python script with a
    `#!...python.exe` shebang, which Windows' CreateProcess cannot
    execute directly the way a POSIX exec() follows a shebang. When no
    .exe exists but the bare script does, invoke it via sys.executable
    explicitly instead.

    Falls back to the bare name (PATH lookup) when neither exists
    locally — e.g. the Docker image's system-wide install, where
    sys.exec_prefix already resolves correctly on its own.
    """
    bin_dir = "Scripts" if os.name == "nt" else "bin"

    exe_candidate = Path(sys.exec_prefix) / bin_dir / f"{name}{'.exe' if os.name == 'nt' else ''}"
    if exe_candidate.exists():
        return [str(exe_candidate)]

    script_candidate = Path(sys.exec_prefix) / bin_dir / name
    if script_candidate.exists():
        return [sys.executable, str(script_candidate)]

    return [name]


def _unavailable_finding(tool_name: str, file_path: str, reason: str) -> Finding:
    return Finding.create(
        file=file_path, start_line=0, end_line=0, severity=Severity.LOW,
        source_tool=tool_name, rule_id="internal.tool_unavailable",
        message=f"{tool_name} unavailable: {reason}",
    )


def run_tool_on_file(
    tool_name: str,
    build_cmd: Callable[[str], list[str]],
    parse_output: Callable[[str, str], list[Finding]],
    file_path: str,
    content: str,
    timeout: int,
) -> list[Finding]:
    suffix = Path(file_path).suffix or ".py"
    tmp_path = None
    start = time.perf_counter()
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        proc = subprocess.run(build_cmd(tmp_path), capture_output=True, text=True, timeout=timeout)
        return parse_output(proc.stdout, file_path)
    except subprocess.TimeoutExpired:
        tool_failures_total.labels(tool=tool_name).inc()
        logger.warning("%s timed out after %ds on %s", tool_name, timeout, file_path)
        return [_unavailable_finding(tool_name, file_path, f"timed out after {timeout}s")]
    except Exception as exc:
        tool_failures_total.labels(tool=tool_name).inc()
        logger.exception("%s crashed on %s", tool_name, file_path)
        return [_unavailable_finding(tool_name, file_path, str(exc))]
    finally:
        tool_run_duration_seconds.labels(tool=tool_name).observe(time.perf_counter() - start)
        if tmp_path is not None:
            Path(tmp_path).unlink(missing_ok=True)
