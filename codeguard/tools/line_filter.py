"""Findings come from running tools on the FULL file — Semgrep and
Bandit need real AST/dataflow context, which a single hunk can't give
them. But a PR should only surface what it actually touched, not every
pre-existing issue in code the PR never went near. This filters findings
down to the PR's exact changed-line ranges (narrower than a Hunk's wider
~30-line context window used for LLM review) plus a small margin, since
some tools report a finding's span slightly offset from the literal
changed line (e.g. the line after an added block).
"""

from __future__ import annotations

from codeguard.tools.models import Finding

LINE_CONTEXT = 3


def filter_findings_to_changed_lines(
    findings: list[Finding],
    changed_ranges: dict[str, list[tuple[int, int]]],
) -> list[Finding]:
    kept = []
    for finding in findings:
        if finding.start_line == 0:
            # Meta-findings (e.g. "tool unavailable") aren't about any
            # specific line — always surface them regardless of what
            # changed, since they're operationally important either way.
            kept.append(finding)
            continue

        ranges = changed_ranges.get(finding.file, [])
        if any(
            (start - LINE_CONTEXT) <= finding.start_line <= (start + max(count, 1) - 1 + LINE_CONTEXT)
            for start, count in ranges
        ):
            kept.append(finding)

    return kept
