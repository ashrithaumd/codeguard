"""Regression coverage specific to review_security and the hunk-cache
mechanism it shares with review_ai_aware (_run_verdict_agent) — the
verdict-contract behavior itself (confirm/dismiss, backfill, fail-safe)
is already covered by tests/pipeline/test_ai_aware.py against the
shared _apply_verdicts and isn't re-tested per agent here.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from codeguard.config import RepoConfig
from codeguard.diff.parse import hash_content
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.models import CachedAgentResult
from codeguard.pipeline.nodes import review_security, route_to_security_reviews
from tests.pipeline.conftest import make_finding


def _fake_result(items):
    return AgentCallResult(raw_text=json.dumps(items), tokens_in=10, tokens_out=5, estimated_cost_usd=0.001, latency_s=0.01)


def test_a_failed_call_reports_raw_findings_with_an_explicit_verdict_call_failure():
    """The fail-safe: a failed verdict call still emits the raw tool
    findings, but must say so. AgentCallResult.error is passed through
    verbatim on VerdictCallFailure rather than the caller inferring
    failure from the shape of this dict (which is what cli.py's
    _run_verdict_layer used to do, via the absence of "tokens_in").
    """
    finding = make_finding(file="a.py", tool="bandit", rule_id="B105")
    state = {
        "owner": "o", "repo": "r", "path": "a.py", "content": "x = 1\n", "patch": "",
        "findings": [finding], "hunk_cache_hits": {},
    }
    failed = AgentCallResult(raw_text=None, error="output failed validation (empty/degenerate)", latency_s=0.01)

    with patch("codeguard.pipeline.nodes.call_agent", return_value=failed):
        out = review_security(state)

    assert out["findings"] == [finding]  # raw findings still reported
    assert len(out["verdict_call_failures"]) == 1
    failure = out["verdict_call_failures"][0]
    assert (failure.path, failure.agent) == ("a.py", "security")
    assert failure.reason == "output failed validation (empty/degenerate)"


def test_a_successful_call_reports_no_verdict_call_failure():
    finding = make_finding(file="a.py", tool="bandit", rule_id="B105")
    state = {
        "owner": "o", "repo": "r", "path": "a.py", "content": "x = 1\n", "patch": "",
        "findings": [finding], "hunk_cache_hits": {},
    }
    ok = _fake_result([{"rule_id": "B105", "verdict": "confirmed", "severity": "low", "message": "real"}])

    with patch("codeguard.pipeline.nodes.call_agent", return_value=ok):
        out = review_security(state)

    assert "verdict_call_failures" not in out


def test_route_to_security_reviews_dispatches_regardless_of_ai_markers():
    """Unlike review_ai_aware, review_security isn't gated on
    touches_ai_code — Bandit's generic Python security applies to any
    file, AI-touching or not.
    """
    state = {
        "repo_config": RepoConfig(),
        "owner": "o", "repo": "r",
        "files": {"app/plain.py": "def add(a, b):\n    return a + b\n"},
        "patches": {},
        "tool_findings": [make_finding(file="app/plain.py", tool="bandit", rule_id="B105")],
        "hunk_cache_hits": {},
    }

    sends = route_to_security_reviews(state)

    assert len(sends) == 1
    assert sends[0].arg["path"] == "app/plain.py"


def test_route_to_security_reviews_skips_files_with_no_bandit_findings():
    state = {
        "repo_config": RepoConfig(),
        "owner": "o", "repo": "r",
        "files": {"app/plain.py": "def add(a, b):\n    return a + b\n"},
        "patches": {},
        "tool_findings": [make_finding(file="app/plain.py", tool="ruff", rule_id="E501")],
    }

    assert route_to_security_reviews(state) == []


def test_review_security_confirmed_verdict():
    finding = make_finding(file="app/db.py", rule_id="B608", tool="bandit", message="possible SQL injection")
    model_items = [{"rule_id": "B608", "verdict": "confirmed", "severity": "high", "message": "real SQLi, string-built query"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)):
        result = review_security({
            "owner": "o", "repo": "r", "path": "app/db.py", "content": "x = 1\n",
            "patch": "", "findings": [finding], "hunk_cache_hits": {},
        })

    assert len(result["findings"]) == 1
    assert result["findings"][0].source_tool == "security"
    assert result["cache_writes"][0].agent == "security"


def test_review_security_hunk_cache_hit_skips_the_call():
    finding = make_finding(file="app/db.py", rule_id="B608", tool="bandit")
    content = "x = 1\n"
    cached_finding = make_finding(file="app/db.py", rule_id="B608", tool="security", message="cached")
    hits = {("app/db.py", hash_content(content), "security"): CachedAgentResult(findings=[cached_finding])}

    with patch("codeguard.pipeline.nodes.call_agent") as mock_call:
        result = review_security({
            "owner": "o", "repo": "r", "path": "app/db.py", "content": content,
            "patch": "", "findings": [finding], "hunk_cache_hits": hits,
        })

    mock_call.assert_not_called()
    assert result["findings"] == [cached_finding]
    assert "cache_writes" not in result


def test_review_security_hunk_cache_miss_queues_a_cache_write():
    finding = make_finding(file="app/db.py", rule_id="B608", tool="bandit")
    content = "x = 1\n"
    model_items = [{"rule_id": "B608", "verdict": "confirmed", "severity": "high", "message": "real issue"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)):
        result = review_security({
            "owner": "o", "repo": "r", "path": "app/db.py", "content": content,
            "patch": "", "findings": [finding], "hunk_cache_hits": {},
        })

    assert len(result["cache_writes"]) == 1
    write = result["cache_writes"][0]
    assert write.content_hash == hash_content(content)
    assert write.owner == "o" and write.repo == "r" and write.path == "app/db.py"


def test_review_security_pins_temperature_to_zero():
    """Verdict-contract agents confirm/dismiss a real tool's findings —
    this should give the same verdict on the same input every time, not
    vary with sampling temperature (found live: nothing anywhere pinned
    this before, so every call ran at the API's own default of 1.0)."""
    finding = make_finding(file="app/db.py", rule_id="B608", tool="bandit")
    model_items = [{"rule_id": "B608", "verdict": "confirmed", "severity": "high", "message": "real issue"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)) as mock_call:
        review_security({
            "owner": "o", "repo": "r", "path": "app/db.py", "content": "x = 1\n",
            "patch": "", "findings": [finding], "hunk_cache_hits": {},
        })

    assert mock_call.call_args.kwargs["temperature"] == 0
