"""Regression coverage for review_quality and review_test — the two
direct-findings (generative, no deterministic tool baseline) agents,
and their shared hunk-level routing/caching (_route_to_hunk_reviews,
_run_generative_agent).
"""

from __future__ import annotations

import json
from unittest.mock import patch

from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.models import CachedAgentResult
from codeguard.pipeline.nodes import review_quality, review_test, route_to_quality_reviews, route_to_test_reviews
from codeguard.severity import Severity
from tests.pipeline.conftest import make_finding


def _fake_result(items):
    return AgentCallResult(raw_text=json.dumps(items), tokens_in=8, tokens_out=4, estimated_cost_usd=0.0005, latency_s=0.01)


def _hunk_state(path="a.py", content="def f(x):\n    return x + 1\n", start_line=1, end_line=2, content_hash="abc123"):
    return {
        "owner": "o", "repo": "r", "path": path, "content": content,
        "content_hash": content_hash, "start_line": start_line, "end_line": end_line,
        "hunk_cache_hits": {},
    }


def test_route_to_quality_reviews_dispatches_one_send_per_hunk():
    state = {
        "owner": "o", "repo": "r",
        "files": {"a.py": "def f(x):\n    return x + 1\n"},
        "patches": {"a.py": "@@ -1,2 +1,2 @@\n context"},
        "hunk_cache_hits": {},
    }

    sends = route_to_quality_reviews(state)

    assert len(sends) == 1
    assert sends[0].node == "review_quality"
    assert sends[0].arg["path"] == "a.py"
    assert "content_hash" in sends[0].arg


def test_route_to_test_reviews_uses_the_same_hunks():
    state = {
        "owner": "o", "repo": "r",
        "files": {"a.py": "def f(x):\n    return x + 1\n"},
        "patches": {"a.py": "@@ -1,2 +1,2 @@\n context"},
        "hunk_cache_hits": {},
    }

    sends = route_to_test_reviews(state)

    assert len(sends) == 1
    assert sends[0].node == "review_test"


def test_review_quality_parses_findings_from_model_output():
    items = [{"line": 1, "severity": "low", "category": "naming", "message": "single-letter parameter name"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f.source_tool == "quality-agent"
    assert f.rule_id == "quality.naming"
    assert f.start_line == 1
    assert len(result["cache_writes"]) == 1


def test_review_quality_clamps_a_line_number_outside_the_hunk_range():
    items = [{"line": 999, "severity": "low", "category": "naming", "message": "out of range"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state(start_line=10, end_line=15))

    assert result["findings"][0].start_line == 15


def test_review_quality_empty_array_means_no_findings_no_fallback():
    """No deterministic tool baseline here — unlike the verdict-contract
    agents, an empty response is just zero findings, not a fallback to
    anything.
    """
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result([])):
        result = review_quality(_hunk_state())

    assert result["findings"] == []


def test_review_test_call_failure_produces_no_findings_and_no_crash():
    with patch("codeguard.pipeline.nodes.call_agent", return_value=AgentCallResult(raw_text=None, error="boom")):
        result = review_test(_hunk_state())

    assert result.get("findings", []) == []
    assert "cache_writes" not in result


def test_review_test_hunk_cache_hit_skips_the_call():
    cached_finding = make_finding(file="a.py", rule_id="test.coverage-gap", tool="test-agent", message="cached")
    hits = {("a.py", "abc123", "test"): CachedAgentResult(findings=[cached_finding])}

    with patch("codeguard.pipeline.nodes.call_agent") as mock_call:
        result = review_test(_hunk_state() | {"hunk_cache_hits": hits})

    mock_call.assert_not_called()
    assert result["findings"] == [cached_finding]


# --- Phase 8: noise budget (Quality/Test are the only ungrounded agents) ---

def test_review_quality_parses_confidence_field():
    items = [{"line": 1, "severity": "low", "category": "naming", "message": "x", "confidence": 0.4}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert result["findings"][0].confidence == 0.4


def test_review_quality_missing_confidence_defaults_to_1():
    items = [{"line": 1, "severity": "low", "category": "naming", "message": "x"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert result["findings"][0].confidence == 1.0


def test_review_quality_clamps_confidence_into_0_1_range():
    items = [{"line": 1, "severity": "low", "category": "naming", "message": "a", "confidence": 5.0}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert result["findings"][0].confidence == 1.0


def test_review_quality_clamps_severity_to_settings_max_severity():
    """An LLM's own opinion is never HIGH/CRITICAL, no matter what it
    reports — settings.quality_test_max_severity defaults to MEDIUM."""
    items = [{"line": 1, "severity": "critical", "category": "structure", "message": "x"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert result["findings"][0].severity == Severity.MEDIUM


def test_review_quality_caps_findings_per_hunk_keeping_the_most_severe_and_confident():
    items = [
        {"line": 1, "severity": "low", "category": "naming", "message": "1", "confidence": 0.9},
        {"line": 1, "severity": "medium", "category": "naming", "message": "2", "confidence": 0.9},
        {"line": 1, "severity": "low", "category": "naming", "message": "3", "confidence": 0.1},
        {"line": 1, "severity": "low", "category": "naming", "message": "4", "confidence": 0.5},
        {"line": 1, "severity": "low", "category": "naming", "message": "5", "confidence": 0.6},
    ]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    findings = result["findings"]
    assert len(findings) == 3  # default noise budget cap
    messages = {f.message for f in findings}
    assert messages == {"2", "1", "5"}  # medium first, then the two highest-confidence lows
