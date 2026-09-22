from __future__ import annotations

from typing import NamedTuple

from pydantic import BaseModel, Field

from codeguard.tools.models import Finding


class VerdictCallFailure(NamedTuple):
    """One verdict-agent call that did not produce a verdict, so the
    file's raw tool findings were reported unverified.

    Exists because the failure was previously inferred from the
    ABSENCE of a "tokens_in" key on the node's return dict (see
    cli.py's _run_verdict_layer). AgentCallResult already carries
    .ok and .error; that signal was being discarded at the node
    boundary and reconstructed one layer up, so any future change
    that happened to add "tokens_in": 0 to the failure path would
    have silently turned audit-mode failure reporting off.

    reason is AgentCallResult.error verbatim (API exception, timeout,
    guardrail refusal, or degenerate output) — not a re-derived
    description of it.
    """
    path: str
    agent: str
    reason: str


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

    # The file and line this replacement was actually written against,
    # captured from the Finding at generation time. A GitHub suggestion
    # block replaces the line its comment is anchored to, so if the
    # finding this is attached to has moved by the time it is posted,
    # the block rewrites the WRONG line -- which is not a cosmetic
    # failure: the reviewer clicks "Commit suggestion" and the file is
    # corrupted. worker/main.py re-checks these against the finding it
    # is about to post and drops the suggestion on any mismatch.
    # Defaulted so older rows/records deserialize, and treated as
    # "unverifiable, keep" in that case rather than silently dropped.
    target_file: str = ""
    target_line: int = -1

    # The LAST line this replacement covers. A correct fix is often
    # wider than the finding that prompted it -- B608 flags the line
    # building the query string, but parameterizing it also has to
    # change the cursor.execute() call below it -- so the replaced range
    # is recorded separately from the finding's own range rather than
    # assumed equal to it. worker/main.py turns a range wider than one
    # line into a multi-line suggestion (start_line..line), which
    # replaces exactly these lines and nothing else.
    # Defaulted to -1, meaning "single line, same as target_line", so
    # older rows/records deserialize unchanged.
    target_end_line: int = -1

    # The lines being replaced, verbatim, as they stood in the file when
    # the suggestion was written. propose_fix has already verified this
    # against the file (_matched_replacement_range), so recording it
    # costs nothing and is the only way anything downstream can show a
    # before/after: the dashboard renders a red/green diff from it, and
    # without it a reader sees the replacement with nothing to compare
    # against. Empty for records written before this field existed, and
    # the dashboard then shows the replacement alone rather than
    # inventing a "before" it does not have.
    original_text: str = ""


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
