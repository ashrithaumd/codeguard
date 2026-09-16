from __future__ import annotations

from pydantic import BaseModel, Field

from codeguard.tools.models import Finding


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


class FixSuggestion(BaseModel):
    """propose_fix's output for one confirmed finding at/above
    fix_threshold — a GitHub suggestion-block body, correlated back to
    the Finding it addresses by fingerprint (Finding.fingerprint is
    already a stable identity; reusing it here avoids inventing a
    second one). Never applied automatically — worker/main.py appends
    `suggestion_body` under that finding's own inline review comment;
    a human still has to click "commit suggestion" on GitHub.
    """
    fingerprint: str
    suggestion_body: str  # a ```suggestion\n...\n``` block, ready to append to a review comment


class CacheWriteRecord(BaseModel):
    """One agent's fresh (non-cache-hit) result for one piece of
    content, queued for worker/main.py to persist to the hunk_findings
    table after the graph run — see codeguard/pipeline/hunk_cache.py.
    Nodes stay pure (no DB access mid-graph, same as every other node
    in this package); this is the state-carried record of "here's what
    to write," not a write itself.
    """
    owner: str
    repo: str
    path: str
    content_hash: str
    agent: str
    findings: list[Finding] = Field(default_factory=list)
    dismissed: list[DismissedFinding] = Field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    estimated_cost_usd: float = 0.0


# (path, content_hash, agent) — the hunk_findings table's own key minus
# (owner, repo), which every lookup within one PR review already shares.
# Defined here (not in hunk_cache.py) so state.py and nodes.py can use
# it without importing anything DB-dependent — hunk_cache.py itself
# imports this rather than redefining it.
CacheKey = tuple[str, str, str]


class CachedAgentResult(BaseModel):
    """A hunk_findings row, reconstructed — what a cache HIT hands back
    to a node instead of it calling the LLM at all. See
    codeguard/pipeline/hunk_cache.py.fetch_cache_hits.
    """
    findings: list[Finding] = Field(default_factory=list)
    dismissed: list[DismissedFinding] = Field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    estimated_cost_usd: float = 0.0
