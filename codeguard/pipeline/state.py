"""State schema for the review pipeline.

`findings`, `repo_level_findings`, `tokens_in`, `tokens_out`,
`estimated_cost_usd`, and `node_latencies` are all `Annotated[...,
operator.add]` — LangGraph's reducer contract for state a parallel
`Send`-based fan-out writes to. Each per-file branch returns a *partial*
state update (its own slice), and LangGraph merges every branch's
update into the parent state via the annotated reducer rather than one
branch's return overwriting another's. Plain (non-Annotated) fields are
set once and not merged across branches — every fan-out branch that
touches one of those must agree, or just not return it at all.

tokens_in/tokens_out/estimated_cost_usd/node_latencies exist now, every
value 0/empty, even though nothing in this phase does an LLM call —
Phase 7's real agents fill them, and defining the shape now means the
state contract doesn't change under Phase 7's feet later.
"""

from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from codeguard.config import RepoConfig
from codeguard.pipeline.models import CachedAgentResult, CacheKey, CacheWriteRecord, DismissedFinding, FixSuggestion
from codeguard.tools.models import Finding


class NodeLatency(TypedDict):
    node: str
    file: str | None
    seconds: float


class FileReviewState(TypedDict):
    """Send payload for one per-file fan-out branch — a narrower slice
    of ReviewState, since each branch only needs this file's own data.
    Used by review_file (Ruff passthrough), review_security (Bandit,
    verdict contract) and review_ai_aware (Semgrep, verdict contract) —
    the three agents scoped to a whole file's already file-level tool
    findings, cached (see hunk_cache_hits) by the whole file's own
    content hash.
    """
    owner: str
    repo: str
    path: str
    content: str
    patch: str
    findings: list[Finding]
    hunk_cache_hits: dict[CacheKey, CachedAgentResult]  # copied in by the router, same dict every branch shares


class HunkReviewState(TypedDict):
    """Send payload for one per-HUNK fan-out branch — review_quality
    and review_test, the two generative (not tool-verifying) agents,
    each reviewing one ~30-line-expanded hunk (codeguard/diff/parse.py's
    build_hunks) rather than a whole file. Cached by the hunk's own
    content_hash, independent of the rest of the file.
    """
    owner: str
    repo: str
    path: str
    content: str  # this hunk's own expanded content block, not the whole file
    content_hash: str
    start_line: int
    end_line: int
    hunk_cache_hits: dict[CacheKey, CachedAgentResult]


class ReviewState(TypedDict):
    owner: str
    repo: str
    pr_number: int
    head_sha: str
    installation_id: int
    repo_config: RepoConfig

    files: dict[str, str]        # path -> full content at head_sha
    patches: dict[str, str]      # path -> GitHub patch text
    tool_findings: list[Finding]  # Phase 4's pre-computed findings for the whole PR, set once

    # Phase 10: fingerprints a repo maintainer has marked false_positive
    # via a reply on a past PR (codeguard/pipeline/feedback.py) — fetched
    # ONCE by worker/main.py before the graph runs, same "set once, not a
    # reducer" shape as hunk_cache_hits. route_after_fanin and summarize
    # both exclude these before deciding fix eligibility / what to show;
    # worker/main.py applies the identical exclusion again on
    # final_state's own findings before computing the Check Run
    # conclusion, since that reads state after the graph has already
    # returned (see _check_run_conclusion's own call site).
    suppressed_fingerprints: frozenset[str]

    # Phase 6: bounded Python-file sample from the PR's BASE branch (see
    # codeguard/github/base_tree.py), used only by review_repo_level's
    # eval-hygiene checks. Empty dict when repo_config.enable_ai_aware is
    # False — worker/main.py skips the fetch entirely in that case.
    base_tree_files: dict[str, str]

    # Phase 7: hunk-level result reuse (codeguard/pipeline/hunk_cache.py).
    # hunk_cache_hits is fetched ONCE by worker/main.py before the graph
    # runs (a node checking its own (path, content_hash, agent) key here
    # instead of calling the LLM at all is what "no LLM call" means) —
    # set once, not a reducer. cache_writes is the reverse direction:
    # every node that made a FRESH call (a miss) appends the record it
    # wants persisted; worker/main.py writes them all back after the
    # graph completes. A cache-hit branch appends nothing here — there's
    # nothing new to write.
    hunk_cache_hits: dict[CacheKey, CachedAgentResult]
    cache_writes: Annotated[list[CacheWriteRecord], operator.add]

    touches_ai_code: bool

    findings: Annotated[list[Finding], operator.add]
    repo_level_findings: Annotated[list[Finding], operator.add]
    # Phase 6.1: Semgrep findings the AI-aware agent judged, in context,
    # not to be real issues — never posted inline, surfaced only in
    # summarize()'s body. See codeguard/pipeline/models.py's
    # DismissedFinding and Settings.ai_aware_dismissals_enabled.
    dismissed_findings: Annotated[list[DismissedFinding], operator.add]
    # Phase 7: propose_fix's suggestion-block output, one per confirmed
    # finding at/above fix_threshold — never applied, just proposed.
    fix_suggestions: Annotated[list[FixSuggestion], operator.add]

    # Annotated, not plain: propose_fix fans out one Send per qualifying
    # file (route_after_fanin), and LangGraph rejects two branches
    # writing the SAME plain key in one superstep even when both would
    # write the identical value True — confirmed the hard way, via a
    # real INVALID_CONCURRENT_GRAPH_UPDATE on a live multi-file PR
    # during Phase 7 verification, not assumed. operator.or_ combines
    # any number of True/False writes correctly; a run where
    # propose_fix never fires at all leaves this at its initial False.
    should_fix: Annotated[bool, operator.or_]
    summary: str
    inline_findings: list[Finding]  # set once by summarize; what the worker actually posts inline

    tokens_in: Annotated[int, operator.add]
    tokens_out: Annotated[int, operator.add]
    estimated_cost_usd: Annotated[float, operator.add]
    node_latencies: Annotated[list[NodeLatency], operator.add]
