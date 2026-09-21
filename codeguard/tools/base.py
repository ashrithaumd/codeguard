"""Shared execution harness for all three tool runners.

Every reviewed file is written into ONE temp directory (preserving
relative paths), and the tool is invoked ONCE for the whole PR, not
once per file — an earlier per-file design measured Semgrep's
rule-loading overhead at ~2s *per file*, almost entirely fixed cost
paid again on every single file. Amortizing it across all of a PR's
files in one invocation is the single biggest lever on tooling latency.

A crash or timeout still never aborts the review — it produces one
"tool unavailable" Finding (now PR-wide, not per-file, since there's
only one invocation to fail) and increments a failure counter.

Deliberately does NOT check the subprocess's exit code: Semgrep,
Bandit, and Ruff all conventionally exit non-zero when they *find
issues* — that is their normal, successful behavior, not a failure.
Only a real execution problem (timeout, the binary missing, unparseable
output) counts as "tool unavailable" here.
"""

from __future__ import annotations

import logging
import os
import shutil
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


def resolve_original_path(tmp_dir: str, reported_path: str) -> str:
    """Tool output reports paths inside the temp directory tools were
    invoked against; convert back to the PR's real relative path,
    forward-slash-normalized regardless of host OS, since findings need
    to match the same path strings diff ingestion already uses.
    """
    try:
        rel = os.path.relpath(reported_path, tmp_dir)
    except ValueError:
        rel = reported_path
    return Path(rel).as_posix()


# Enough of the tool's stderr to identify the real cause without
# flooding the log with a whole scan's worth of output.
_STDERR_TAIL_CHARS = 2000


def _stderr_tail(proc: subprocess.CompletedProcess | None) -> str:
    """The failing tool's own stderr, which used to be discarded
    outright. It is usually the only place the real cause appears: a
    tool that dies before writing JSON leaves stdout empty, so what
    surfaces here is a JSONDecodeError from parse_output -- an error
    about this module's parsing, not about why the tool died. stderr is
    where the actual traceback is.
    """
    stderr = getattr(proc, "stderr", None)
    if not stderr:
        return ""
    return f" stderr_tail={stderr.strip()[-_STDERR_TAIL_CHARS:]!r}"


def _platform_hint(tool_name: str) -> str:
    """Names a known-unfixable platform failure instead of letting it
    read as a transient crash. Semgrep's CLI is a Python script that
    hands off to a compiled semgrep-core via os.execvp(); no such binary
    is shipped for Windows, so the handoff dies with
    FileNotFoundError [Errno 2] and semgrep cannot run on this host at
    all -- no retry, reinstall or PATH fix changes that. Worth saying
    out loud because semgrep owns this project's ENTIRE custom
    llm-security ruleset: when it is the tool that silently didn't run,
    the review keeps its AI-aware framing while having checked none of
    the AI-aware rules.
    """
    if tool_name == "semgrep" and sys.platform == "win32":
        return (
            " CAUSE: semgrep's CLI execs a semgrep-core binary that is not shipped for "
            "Windows, so semgrep cannot run on this host and this review has NO custom "
            "llm-security rule coverage. Run the review inside the Linux container "
            "instead (docker compose exec worker ...)."
        )
    return ""


def _unavailable_finding(tool_name: str, reason: str) -> Finding:
    return Finding.create(
        file="<pr>", start_line=0, end_line=0, severity=Severity.LOW,
        source_tool=tool_name, rule_id="internal.tool_unavailable",
        message=f"{tool_name} unavailable: {reason}",
    )


def run_tool_on_pr(
    tool_name: str,
    build_cmd: Callable[[str], list[str]],
    parse_output: Callable[[str, str], list[Finding]],
    files: dict[str, str],
    timeout: int,
) -> list[Finding]:
    if not files:
        return []

    tmp_dir = tempfile.mkdtemp(prefix=f"codeguard-{tool_name}-")
    start = time.perf_counter()
    # Bound outside the try purely so the failure path can still read the
    # tool's stderr when it was parse_output(), not subprocess.run(),
    # that raised.
    proc: subprocess.CompletedProcess | None = None
    try:
        for rel_path, content in files.items():
            dest = Path(tmp_dir) / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")

        proc = subprocess.run(build_cmd(tmp_dir), capture_output=True, text=True, timeout=timeout)
        return parse_output(proc.stdout, tmp_dir)
    except subprocess.TimeoutExpired:
        tool_failures_total.labels(tool=tool_name).inc()
        logger.warning("%s timed out after %ds on %d file(s)", tool_name, timeout, len(files))
        return [_unavailable_finding(tool_name, f"timed out after {timeout}s")]
    except Exception as exc:
        tool_failures_total.labels(tool=tool_name).inc()
        hint = _platform_hint(tool_name)
        # Deliberately loud: a tool that did not run means the review is
        # INCOMPLETE, not merely that one check was noisy, and the old
        # "semgrep crashed" line named neither the consequence nor the
        # cause.
        logger.error(
            "%s DID NOT RUN on %d file(s) -- this review has no %s coverage. error=%r%s%s",
            tool_name, len(files), tool_name, exc, _stderr_tail(proc), hint,
            exc_info=True,
        )
        return [_unavailable_finding(tool_name, f"{exc}{hint}")]
    finally:
        tool_run_duration_seconds.labels(tool=tool_name).observe(time.perf_counter() - start)
        shutil.rmtree(tmp_dir, ignore_errors=True)
