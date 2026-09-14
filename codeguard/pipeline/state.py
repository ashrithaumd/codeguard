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
from codeguard.tools.models import Finding


class NodeLatency(TypedDict):
    node: str
    file: str | None
    seconds: float


class FileReviewState(TypedDict):
    """Send payload for one per-file fan-out branch — a narrower slice
    of ReviewState, since each branch only needs this file's own data.
    Phase 7's real per-file agents will use `content` and `patch`
    directly; Phase 5's stub only needs `findings` (this file's slice
    of the tool findings, pre-filtered by path before dispatch).
    """
    owner: str
    repo: str
    path: str
    content: str
    patch: str
    findings: list[Finding]


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

    touches_ai_code: bool

    findings: Annotated[list[Finding], operator.add]
    repo_level_findings: Annotated[list[Finding], operator.add]

    should_fix: bool
    summary: str
    inline_findings: list[Finding]  # set once by summarize; what the worker actually posts inline

    tokens_in: Annotated[int, operator.add]
    tokens_out: Annotated[int, operator.add]
    estimated_cost_usd: Annotated[float, operator.add]
    node_latencies: Annotated[list[NodeLatency], operator.add]
