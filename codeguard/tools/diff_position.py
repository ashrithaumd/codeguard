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
