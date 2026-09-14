"""Maps a Finding to the position GitHub's review-comment API needs to
post it inline. Kept in exactly one place — per the requirement — so
Phase 5 and anything else that posts findings never reimplements this.

Deliberately simple: Finding.start_line is already a real line number in
the file at head_sha (tools ran on the full file, not a diff-relative
offset), so GitHub's modern line+side review-comment API maps onto it
directly with no transformation. (GitHub's older `position` field — an
offset counted through the unified diff text itself — would need real
translation logic; line+side doesn't.)
"""

from __future__ import annotations

from pydantic import BaseModel

from codeguard.tools.models import Finding


class DiffPosition(BaseModel):
    path: str
    line: int
    side: str  # "RIGHT" — findings are always against head_sha, the new/right side


def map_finding_to_diff_position(finding: Finding) -> DiffPosition:
    return DiffPosition(path=finding.file, line=finding.start_line, side="RIGHT")


def is_line_in_diff(file: str, line: int, changed_ranges: dict[str, list[tuple[int, int]]]) -> bool:
    """Whether `line` is actually part of the diff GitHub computed for
    `file` — required for an inline review comment to succeed at all;
    GitHub rejects a comment on a line outside the diff. Deliberately
    NO extra margin here, unlike line_filter.py's relevance filtering
    (which intentionally widens by LINE_CONTEXT to catch findings just
    outside the exact change): changed_ranges already includes GitHub's
    own small natural context from each hunk header, and widening
    further would let us attempt a comment GitHub will actually 422 on.
    A finding that fails this check still gets reported — see
    codeguard/pipeline/nodes.py's summarize — just in the review's
    summary body instead of inline, never silently dropped and never a
    failed API call.
    """
    for start, count in changed_ranges.get(file, []):
        if start <= line <= start + max(count, 1) - 1:
            return True
    return False
