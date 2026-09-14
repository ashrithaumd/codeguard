"""Orchestrates all three deterministic tool runners against a PR's
reviewed files and filters the combined output down to changed lines.
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

    all_findings: list[Finding] = []
    for path, content in files.items():
        for runner in RUNNERS:
            # Each is a blocking subprocess call — to_thread keeps the
            # event loop (and this job's heartbeat task) unblocked.
            findings = await asyncio.to_thread(runner, path, content)
            all_findings.extend(findings)

    filtered = filter_findings_to_changed_lines(all_findings, changed_ranges)
    for f in filtered:
        findings_total.labels(tool=f.source_tool, severity=f.severity.name).inc()
    return filtered
