from __future__ import annotations

from pydantic import BaseModel


class DismissedFinding(BaseModel):
    """A Semgrep finding the AI-aware agent judged, in context, not to
    be a real issue — recorded rather than silently discarded, so the
    PR summary can show reviewers what was checked and why it wasn't
    flagged, not just what was. Never posted inline; surfaced only in
    summarize()'s body as "checked, not flagged."

    Settings.ai_aware_dismissals_enabled is the fail-safe override: when
    False, review_ai_aware never produces one of these — every finding
    the model would have dismissed instead falls back to a confirmed
    raw Semgrep Finding via the same unaddressed-rule_id path a finding
    the model never mentions at all already goes through.
    """
    file: str
    start_line: int
    rule_id: str
    reason: str
