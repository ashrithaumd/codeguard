"""Builds the review graph.

Topology:

    START -> classify
    classify -> [Send fan-out] -> review_file       (per file: Ruff + unclaimed findings)
    classify -> [Send fan-out] -> review_security    (per file with Bandit findings)
    classify -> [Send fan-out] -> review_ai_aware    (per AI-touching file, gated)
    classify -> [Send fan-out] -> review_quality     (per HUNK, Haiku)
    classify -> [Send fan-out] -> review_test        (per HUNK, Haiku)
    classify -> review_repo_level                    (always runs once)
    {review_file, review_security, review_ai_aware, review_quality, review_test,
     review_repo_level} -> check_findings             (LangGraph joins all here)
    check_findings -> [conditional] -> propose_fix (Send, per qualifying file) | summarize
    propose_fix -> summarize
    summarize -> END

check_findings is a real (if trivial) join node rather than relying on
conditional-edge sources converging directly — explicit and easy to
verify empirically (confirmed every phase so far: summarize runs
exactly once per PR, not once per file/hunk, by checking review logs).

Every Send-based branch above contributes nothing to the join when it
has nothing to dispatch (no files, no AI-touching files, no Bandit
findings, enable_ai_aware off) — the same "zero Sends -> no join
contribution" behavior route_to_file_reviews has relied on since
Phase 5 for an empty `files` dict.

route_after_fanin is the one router that returns EITHER a plain string
("summarize", when nothing meets fix_threshold) OR a list[Send]
(propose_fix per qualifying file) from the same function — confirmed
empirically (a standalone LangGraph smoke test, not just read from
docs) that a conditional edge can mix both return shapes correctly,
including the join edge from propose_fix into summarize firing exactly
once after however many Sends actually fired.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from codeguard.pipeline.nodes import (
    check_findings,
    classify,
    propose_fix,
    review_ai_aware,
    review_file,
    review_quality,
    review_repo_level,
    review_security,
    review_test,
    route_after_fanin,
    route_to_ai_aware_reviews,
    route_to_file_reviews,
    route_to_quality_reviews,
    route_to_security_reviews,
    route_to_test_reviews,
    summarize,
)
from codeguard.pipeline.state import ReviewState


def build_review_graph():
    graph = StateGraph(ReviewState)

    graph.add_node("classify", classify)
    graph.add_node("review_file", review_file)
    graph.add_node("review_security", review_security)
    graph.add_node("review_ai_aware", review_ai_aware)
    graph.add_node("review_quality", review_quality)
    graph.add_node("review_test", review_test)
    graph.add_node("review_repo_level", review_repo_level)
    graph.add_node("check_findings", check_findings)
    graph.add_node("propose_fix", propose_fix)
    graph.add_node("summarize", summarize)

    graph.add_edge(START, "classify")
    graph.add_conditional_edges("classify", route_to_file_reviews, ["review_file"])
    graph.add_conditional_edges("classify", route_to_security_reviews, ["review_security"])
    graph.add_conditional_edges("classify", route_to_ai_aware_reviews, ["review_ai_aware"])
    graph.add_conditional_edges("classify", route_to_quality_reviews, ["review_quality"])
    graph.add_conditional_edges("classify", route_to_test_reviews, ["review_test"])
    graph.add_edge("classify", "review_repo_level")

    graph.add_edge("review_file", "check_findings")
    graph.add_edge("review_security", "check_findings")
    graph.add_edge("review_ai_aware", "check_findings")
    graph.add_edge("review_quality", "check_findings")
    graph.add_edge("review_test", "check_findings")
    graph.add_edge("review_repo_level", "check_findings")

    graph.add_conditional_edges("check_findings", route_after_fanin, ["propose_fix", "summarize"])
    graph.add_edge("propose_fix", "summarize")
    graph.add_edge("summarize", END)

    return graph.compile()


review_graph = build_review_graph()
