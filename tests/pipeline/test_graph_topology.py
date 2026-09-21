"""Regression coverage for the graph's own shape — not just what the
nodes happen to return, but that Send-based fan-out dispatches the
right number of branches, the repo-level branch runs exactly once
regardless of file/hunk count, and the conditional fix edge is taken
(or not) purely based on severity vs threshold. No GitHub calls
anywhere: the graph itself never touches the network — posting happens
in the worker, outside review_graph.ainvoke(). Every LLM call in this
module goes through a mocked call_agent (see _mock_call_agent) so the
whole test file runs with zero network calls and zero cost, same as
every other file under tests/pipeline/.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from codeguard.config import RepoConfig
from codeguard.pipeline.graph import build_review_graph, review_graph
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.severity import Severity
from tests.pipeline.conftest import make_finding


def _mock_call_agent(*, agent, **kwargs):
    """Every agent gets a valid-but-empty response — verdict-contract
    agents (security/ai_aware) fall back to their raw findings,
    confirmed (see _apply_verdicts); direct-findings agents (quality/
    test) contribute nothing; fix contributes no suggestions but still
    marks should_fix; summary's "[]" just becomes an odd-looking but
    harmless intro string — none of that matters for topology tests.
    """
    return AgentCallResult(raw_text="[]", tokens_in=1, tokens_out=1, estimated_cost_usd=0.0, latency_s=0.0)


@pytest.fixture(autouse=True)
def _no_network_llm_calls():
    with patch("codeguard.pipeline.nodes.call_agent", side_effect=_mock_call_agent):
        yield


def _base_state(files, tool_findings=None, repo_config=None):
    return {
        "owner": "o", "repo": "r", "pr_number": 1, "head_sha": "sha", "installation_id": 1,
        "repo_config": repo_config or RepoConfig(),
        "files": files,
        "patches": {
            path: f"@@ -1,{len(content.splitlines()) or 1} +1,{len(content.splitlines()) or 1} @@\n context"
            for path, content in files.items()
        },
        "tool_findings": tool_findings or [], "base_tree_files": {},
        "budget_exceeded": False,
        "hunk_cache_hits": {}, "cache_writes": [],
        "suppressed_fingerprints": frozenset(),
        "touches_ai_code": False,
        "findings": [], "repo_level_findings": [], "dismissed_findings": [], "fix_suggestions": [],
        "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
    }


@pytest.mark.parametrize("file_count", [1, 3, 5])
async def test_fanout_produces_exactly_one_review_per_file(file_count):
    """Ruff findings specifically: review_file's own passthrough is the
    only agent that forwards them unchanged (security claims bandit,
    ai_aware claims semgrep on AI files) — quality/test still fan out
    per hunk under the mock but contribute zero findings, so the total
    stays attributable to review_file alone.
    """
    files = {f"f{i}.py": f"line{i}\n" for i in range(file_count)}
    findings = [make_finding(file=f"f{i}.py", line=1, tool="ruff") for i in range(file_count)]
    state = _base_state(files, tool_findings=findings)

    result = await review_graph.ainvoke(state)

    assert len(result["findings"]) == file_count
    assert {f.file for f in result["findings"]} == set(files.keys())


async def test_repo_level_branch_runs_exactly_once_regardless_of_file_count():
    """A stub that always returns [] can't prove invocation count from
    its output alone (empty + empty + empty is still empty) — so this
    patches in a counting wrapper at the graph module's import site
    (where `add_node` actually resolves the name) and rebuilds the
    graph under that patch.
    """
    call_count = {"n": 0}

    def counting_repo_level(state):
        call_count["n"] += 1
        return {"repo_level_findings": []}

    with patch("codeguard.pipeline.graph.review_repo_level", counting_repo_level):
        graph = build_review_graph()
        files = {f"f{i}.py": "x\n" for i in range(4)}
        await graph.ainvoke(_base_state(files))

    assert call_count["n"] == 1


async def test_fix_edge_taken_when_max_severity_meets_threshold():
    files = {"a.py": "x\n"}
    findings = [make_finding(file="a.py", line=1, severity=Severity.HIGH, tool="bandit")]
    state = _base_state(files, tool_findings=findings, repo_config=RepoConfig(fix_threshold=Severity.HIGH))

    result = await review_graph.ainvoke(state)

    assert result["should_fix"] is True


async def test_fix_edge_not_taken_when_below_threshold():
    files = {"a.py": "x\n"}
    findings = [make_finding(file="a.py", line=1, severity=Severity.LOW, tool="bandit")]
    state = _base_state(files, tool_findings=findings, repo_config=RepoConfig(fix_threshold=Severity.HIGH))

    result = await review_graph.ainvoke(state)

    assert result["should_fix"] is False


async def test_fix_edge_not_taken_when_no_findings_at_all():
    files = {"a.py": "x\n"}
    state = _base_state(files, tool_findings=[])

    result = await review_graph.ainvoke(state)

    assert result["should_fix"] is False


async def test_security_agent_fans_out_only_for_files_with_bandit_findings():
    """route_to_security_reviews dispatches per file with a Bandit
    finding, regardless of touches_ai_code — unlike review_ai_aware.
    """
    files = {"a.py": "x\n", "b.py": "y\n"}
    findings = [make_finding(file="a.py", line=1, tool="bandit", rule_id="B105")]
    state = _base_state(files, tool_findings=findings)

    result = await review_graph.ainvoke(state)

    # the mock falls back the bandit finding through unaddressed, confirmed
    assert any(f.file == "a.py" and f.rule_id == "B105" for f in result["findings"])
    assert not any(f.file == "b.py" for f in result["findings"])


async def test_ai_aware_agent_fans_out_only_for_ai_touching_files():
    files = {"assistant.py": "import anthropic\n", "plain.py": "def add(a, b):\n    return a + b\n"}
    findings = [make_finding(file="assistant.py", line=1, tool="semgrep", rule_id="llm-unpinned-model-alias")]
    state = _base_state(files, tool_findings=findings)

    result = await review_graph.ainvoke(state)

    assert any(f.file == "assistant.py" and f.rule_id == "llm-unpinned-model-alias" for f in result["findings"])
