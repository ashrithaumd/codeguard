"""Node and routing functions for the review graph. Every agent here is
a Phase 5 stub per the build plan — classify's heuristic is real and
permanent, but review_file/review_repo_level/fix do no real analysis
yet. Phase 6 (AI-aware agent, eval-hygiene) and Phase 7 (Security/
Quality/Test/Fix agents) fill these in without changing the graph
shape or the state contract.
"""

from __future__ import annotations

import logging

from langgraph.types import Send

from codeguard.config import get_settings
from codeguard.diff.parse import parse_hunk_ranges
from codeguard.pipeline.state import ReviewState
from codeguard.tools.diff_position import is_line_in_diff

logger = logging.getLogger(__name__)

_AI_IMPORT_MARKERS = ("anthropic", "openai", "langchain", "langgraph")


def classify(state: ReviewState) -> dict:
    """Real, permanent logic (not a stub): does this PR touch AI code
    at all. Phase 6's AI-aware agent hangs off this — for now it just
    sets the flag; nothing branches on it yet.
    """
    touches_ai = any(
        any(marker in content for marker in _AI_IMPORT_MARKERS)
        for content in state["files"].values()
    )
    return {"touches_ai_code": touches_ai}


def route_to_file_reviews(state: ReviewState) -> list[Send]:
    """Send-based fan-out: one review_file dispatch per reviewed file,
    each carrying only that file's own slice of state (FileReviewState)
    — not the whole graph state. This is the real per-file parallelism
    seam Phase 7's Security/Quality/Test agents will use; Phase 5 just
    proves the mechanism with a pass-through stub.
    """
    sends = []
    for path, content in state["files"].items():
        file_findings = [f for f in state["tool_findings"] if f.file == path]
        sends.append(Send("review_file", {
            "owner": state["owner"],
            "repo": state["repo"],
            "path": path,
            "content": content,
            "patch": state["patches"].get(path, ""),
            "findings": file_findings,
        }))
    return sends


def review_file(state: dict) -> dict:
    """Stub for Phase 7's real per-file Security/Quality/Test agents —
    for now, just passes Phase 4's already-computed tool findings for
    this one file through into the graph's accumulating `findings`
    list. Proves the Send fan-out + operator.add reducer merge
    end to end: N parallel invocations, each returning a partial
    update, correctly summed rather than overwriting each other.
    """
    return {"findings": state["findings"]}


def review_repo_level(state: ReviewState) -> dict:
    """Stub for Phase 6/7's eval-hygiene / repo-level checks — runs
    once per PR, not fanned out. No real checks yet.
    """
    return {"repo_level_findings": []}


def check_findings(state: ReviewState) -> dict:
    """Explicit join node: both the per-file fan-out (N review_file
    instances) and the repo-level branch have a plain edge into this
    node, so LangGraph waits for all of them before it runs — the
    convergence point the architecture calls "merging at summarize."
    No-op beyond existing as that convergence point; the actual
    fix/summarize decision is a conditional edge from here.
    """
    return {}


def route_after_fanin(state: ReviewState) -> str:
    """Conditional edge: only visit `fix` if the worst finding meets
    the repo's own fix_threshold."""
    all_findings = state["findings"] + state["repo_level_findings"]
    if not all_findings:
        return "summarize"
    worst = max(f.severity for f in all_findings)
    if worst >= state["repo_config"].fix_threshold:
        return "fix"
    return "summarize"


def fix(state: ReviewState) -> dict:
    """Stub for Phase 7's real Fix agent. The conditional edge into
    this node already works end to end; the node itself doesn't
    rewrite any code yet.
    """
    return {"should_fix": True}


def summarize(state: ReviewState) -> dict:
    """Dedupes findings by fingerprint, splits them into what can go
    inline (a real diff line, under the per-review cap) versus what
    goes into the summary body instead — never dropped, never a failed
    GitHub API call for commenting on a line outside the diff. Always
    produces a body, even with zero findings, so a clean PR gets an
    explicit "reviewed, nothing found" rather than silence that reads
    as CodeGuard not having run at all.
    """
    settings = get_settings()
    all_findings = state["findings"] + state["repo_level_findings"]

    seen: set[str] = set()
    deduped = []
    for f in all_findings:
        if f.fingerprint not in seen:
            seen.add(f.fingerprint)
            deduped.append(f)

    file_count = len(state["files"])

    if not deduped:
        body = f"CodeGuard reviewed {file_count} file(s), no issues found."
        return {"summary": body, "inline_findings": []}

    changed_ranges = {path: parse_hunk_ranges(patch) for path, patch in state["patches"].items()}

    inlineable = [f for f in deduped if f.start_line > 0 and is_line_in_diff(f.file, f.start_line, changed_ranges)]
    meta_or_outside_diff = [f for f in deduped if f not in inlineable]

    inlineable.sort(key=lambda f: -f.severity)
    to_inline = inlineable[:settings.max_inline_comments]
    overflow = inlineable[settings.max_inline_comments:]

    body_lines = [f"CodeGuard reviewed {file_count} file(s), found {len(deduped)} issue(s)."]
    remainder = overflow + meta_or_outside_diff
    if remainder:
        body_lines.append("")
        body_lines.append(f"{len(remainder)} additional finding(s) not shown inline:")
        for f in remainder:
            location = f"{f.file}:{f.start_line}" if f.start_line > 0 else f.file
            body_lines.append(f"- {location} [{f.source_tool}/{f.severity.name}] {f.rule_id}: {f.message}")

    return {"summary": "\n".join(body_lines), "inline_findings": to_inline}
