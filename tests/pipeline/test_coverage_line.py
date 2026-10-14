"""The PR summary's one coverage line, and the worker's count behind it.

"Secrets only, no code scanner: Go 2, Kotlin 1." appears only when a changed
file is in a language no scanner covers. A PR with nothing uncovered gets
exactly the summary it always got.
"""

from __future__ import annotations

from unittest.mock import patch

from codeguard.config import RepoConfig
from codeguard.diff.models import FilteredFile
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.nodes import summarize
from codeguard.worker.main import coverage_gaps
from tests.pipeline.conftest import make_finding


def _intro(**kwargs):
    return AgentCallResult(raw_text="Intro.", tokens_in=1, tokens_out=1, estimated_cost_usd=0.0, latency_s=0.0)


def _state(findings=(), **over):
    state = {
        "owner": "o", "repo": "r", "pr_number": 1, "head_sha": "sha", "installation_id": 1,
        "repo_config": RepoConfig(), "files": {"a.py": "x = 1\n"}, "patches": {"a.py": "@@ -1,3 +1,3 @@\n x"},
        "tool_findings": [], "touches_ai_code": False, "findings": list(findings), "repo_level_findings": [],
        "dismissed_findings": [], "fix_suggestions": [], "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
        "suppressed_fingerprints": frozenset(), "budget_exceeded": False,
    }
    state.update(over)
    return state


def _summary(state):
    with patch("codeguard.pipeline.nodes.call_agent", side_effect=_intro):
        return summarize(state)["summary"]


def test_the_line_lists_each_uncovered_language_with_a_count():
    text = _summary(_state(coverage_gaps={"Kotlin": 1, "Go": 2}))
    assert "Secrets only, no code scanner: Go 2, Kotlin 1." in text


def test_the_line_is_there_with_findings_too():
    text = _summary(_state([make_finding(file="a.py", line=1)], coverage_gaps={"Go": 1}))
    assert "Secrets only, no code scanner: Go 1." in text


def test_nothing_uncovered_means_the_summary_is_exactly_as_before():
    for findings in ([], [make_finding(file="a.py", line=1)]):
        before = _summary(_state(findings))
        assert _summary(_state(findings, coverage_gaps={})) == before
        assert "Secrets only" not in before


def test_the_worker_counts_uncovered_files_by_language():
    filtered = [
        FilteredFile(path="cmd/main.go", reason="Secrets only (Go)"),
        FilteredFile(path="pkg/x.go", reason="Secrets only (Go)"),
        FilteredFile(path="App.kt", reason="Secrets only (Kotlin)"),
        FilteredFile(path="README.md", reason="lockfile/generated/docs/vendored"),
        FilteredFile(path="data.json", reason="not source code"),
    ]
    assert coverage_gaps(filtered) == {"Go": 2, "Kotlin": 1}
