"""Builds the review graph.

Topology:

    START -> classify
    classify -> [Send fan-out] -> review_file (N parallel, one per file)
    classify -> [Send fan-out] -> review_ai_aware (parallel, one per AI-touching file)
    classify -> review_repo_level                (parallel branch, always runs)
    review_file -> check_findings                (LangGraph joins all here)
    review_ai_aware -> check_findings
    review_repo_level -> check_findings
    check_findings -> [conditional] -> fix | summarize
    fix -> summarize
    summarize -> END

check_findings is a real (if trivial) join node rather than relying on
conditional-edge sources converging directly — explicit and easy to
verify empirically (confirmed: summarize runs exactly once per PR, not
once per file, by checking review logs against file count).

Phase 6 added review_ai_aware as a third parallel branch off classify:
zero Sends (and so no join contribution) when no file touches AI code
or repo_config.enable_ai_aware is off — the same "runs conditionally,
contributes nothing when it doesn't fire" behavior route_to_file_reviews
already relies on for an empty `files` dict.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from codeguard.pipeline.nodes import (
    check_findings,
    classify,
    fix,
    review_ai_aware,
    review_file,
    review_repo_level,
    route_after_fanin,
    route_to_ai_aware_reviews,
    route_to_file_reviews,
    summarize,
)
from codeguard.pipeline.state import ReviewState


def build_review_graph():
    graph = StateGraph(ReviewState)

    graph.add_node("classify", classify)
    graph.add_node("review_file", review_file)
    graph.add_node("review_ai_aware", review_ai_aware)
    graph.add_node("review_repo_level", review_repo_level)
    graph.add_node("check_findings", check_findings)
    graph.add_node("fix", fix)
    graph.add_node("summarize", summarize)

    graph.add_edge(START, "classify")
    graph.add_conditional_edges("classify", route_to_file_reviews, ["review_file"])
    graph.add_conditional_edges("classify", route_to_ai_aware_reviews, ["review_ai_aware"])
    graph.add_edge("classify", "review_repo_level")
    graph.add_edge("review_file", "check_findings")
    graph.add_edge("review_ai_aware", "check_findings")
    graph.add_edge("review_repo_level", "check_findings")
    graph.add_conditional_edges("check_findings", route_after_fanin, ["fix", "summarize"])
    graph.add_edge("fix", "summarize")
    graph.add_edge("summarize", END)

    return graph.compile()


review_graph = build_review_graph()
