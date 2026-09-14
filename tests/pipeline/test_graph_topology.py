"""Regression coverage for the graph's own shape — not just what the
stub nodes happen to return, but that Send-based fan-out dispatches
exactly one branch per file, the repo-level branch runs exactly once
regardless of file count, and the conditional fix edge is taken (or
not) purely based on severity vs threshold. No GitHub calls anywhere:
the graph itself never touches the network — posting happens in the
worker, outside review_graph.ainvoke().
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from codeguard.config import RepoConfig
from codeguard.pipeline.graph import build_review_graph, review_graph
from codeguard.severity import Severity
from tests.pipeline.conftest import make_finding


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
        "touches_ai_code": False, "findings": [], "repo_level_findings": [],
        "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
    }


@pytest.mark.parametrize("file_count", [1, 3, 5])
async def test_fanout_produces_exactly_one_review_per_file(file_count):
    files = {f"f{i}.py": f"line{i}\n" for i in range(file_count)}
    findings = [make_finding(file=f"f{i}.py", line=1) for i in range(file_count)]
    state = _base_state(files, tool_findings=findings)

    result = await review_graph.ainvoke(state)

    # Not just a count check: each file's own finding must have survived
    # fan-out attributed to the RIGHT file, not just the right quantity.
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
    findings = [make_finding(file="a.py", line=1, severity=Severity.HIGH)]
    state = _base_state(files, tool_findings=findings, repo_config=RepoConfig(fix_threshold=Severity.HIGH))

    result = await review_graph.ainvoke(state)

    assert result["should_fix"] is True


async def test_fix_edge_not_taken_when_below_threshold():
    files = {"a.py": "x\n"}
    findings = [make_finding(file="a.py", line=1, severity=Severity.LOW)]
    state = _base_state(files, tool_findings=findings, repo_config=RepoConfig(fix_threshold=Severity.HIGH))

    result = await review_graph.ainvoke(state)

    assert result["should_fix"] is False


async def test_fix_edge_not_taken_when_no_findings_at_all():
    files = {"a.py": "x\n"}
    state = _base_state(files, tool_findings=[])

    result = await review_graph.ainvoke(state)

    assert result["should_fix"] is False
