"""Orchestrates all three deterministic tool runners against a PR's
reviewed files and filters the combined output down to changed lines.

Each tool is invoked ONCE for the whole PR (see base.py's
run_tool_on_pr) rather than once per file, and the three tools run
CONCURRENTLY with each other via asyncio.gather — Semgrep, Bandit, and
Ruff have no shared state, so there's no reason one has to wait on
another.
"""

from __future__ import annotations

import asyncio
import logging

from codeguard.diff.parse import parse_hunk_ranges
from codeguard.tools.bandit_runner import run_bandit
from codeguard.tools.line_filter import filter_findings_to_changed_lines
from codeguard.tools.metrics import findings_total
from codeguard.tools.models import Finding
from codeguard.tools.ruff_runner import run_ruff
from codeguard.tools.semgrep_runner import run_semgrep

logger = logging.getLogger(__name__)

RUNNERS = (run_semgrep, run_bandit, run_ruff)


async def run_tools_on_files(files: dict[str, str], patches: dict[str, str]) -> list[Finding]:
    """files: path -> full content at head_sha (DiffIngestionResult.file_contents).
    patches: path -> that file's GitHub patch text (DiffIngestionResult.patches),
    used only to compute exact changed-line ranges for filtering.
    """
    changed_ranges = {path: parse_hunk_ranges(patch) for path, patch in patches.items()}

    # Each runner is a blocking subprocess call — to_thread keeps the
    # event loop (and this job's heartbeat task) unblocked; gather runs
    # all three tools concurrently with each other, not sequentially.
    results = await asyncio.gather(*(asyncio.to_thread(runner, files) for runner in RUNNERS))
    all_findings: list[Finding] = [f for tool_findings in results for f in tool_findings]

    filtered = filter_findings_to_changed_lines(all_findings, changed_ranges)
    for f in filtered:
        findings_total.labels(tool=f.source_tool, severity=f.severity.name).inc()
    return filtered
