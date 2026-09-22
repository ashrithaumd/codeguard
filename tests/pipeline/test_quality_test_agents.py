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
from codeguard.pipeline.nodes import (
    generative_cache_agent,
    review_quality,
    review_test,
    route_to_quality_reviews,
    route_to_test_reviews,
)
from codeguard.severity import Severity
from tests.pipeline.conftest import make_finding


def _fake_result(items):
    return AgentCallResult(raw_text=json.dumps(items), tokens_in=8, tokens_out=4, estimated_cost_usd=0.0005, latency_s=0.01)


def _fake_raw_result(raw_text):
    return AgentCallResult(raw_text=raw_text, tokens_in=8, tokens_out=4, estimated_cost_usd=0.0005, latency_s=0.01)


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
    items = [{"line": 1, "code": "def f(x):", "severity": "low", "category": "naming", "message": "single-letter parameter name"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f.source_tool == "quality-agent"
    assert f.rule_id == "quality.naming"
    assert f.start_line == 1
    assert len(result["cache_writes"]) == 1


def test_review_quality_demotes_a_line_number_outside_the_hunk_range():
    """This used to assert the opposite -- that the line was CLAMPED to
    the nearest hunk edge (15 here). That is what shipped, and it
    corrupted a live review: a quality finding about line 13 was pinned
    to line 2 because line 2 ended its hunk, then collected a fix
    suggestion whose replacement was written for line 13. See
    tests/pipeline/test_fix_suggestion_targeting.py for the full case.

    A line this branch cannot place is not placed. 0 routes the finding
    to the summary body, where it is still reported in full.
    """
    items = [{"line": 999, "code": "nothing like this", "severity": "low",
              "category": "naming", "message": "out of range"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state(start_line=10, end_line=15))

    f = result["findings"][0]
    assert f.start_line == 0
    assert f.message == "out of range"   # kept, not dropped


def test_review_quality_demotes_a_finding_with_no_line_echo():
    """The `code` echo is what places a finding now, so a response that
    omits it has nothing to place the finding by — even when its line
    number is perfectly plausible.
    """
    items = [{"line": 1, "severity": "low", "category": "naming", "message": "no echo"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    f = result["findings"][0]
    assert f.start_line == 0
    assert f.message == "no echo"


def test_review_quality_relocates_a_finding_to_the_line_it_quoted():
    """The model's line number and its echo disagree; the file settles
    it. Not the old clamp: that moved findings to a hunk edge on no
    evidence, this moves one to the single line whose text the model
    itself quoted.
    """
    items = [{"line": 1, "code": "return x + 1", "severity": "low",
              "category": "naming", "message": "about the return"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert result["findings"][0].start_line == 2


def test_review_quality_demotes_when_the_echo_is_ambiguous():
    """The echo matches two lines and the claimed line is neither, so
    relocating would mean picking one — it fails closed instead.
    """
    content = "x = compute()\ny = 1\nx = compute()\n"
    items = [{"line": 2, "code": "x = compute()", "severity": "low",
              "category": "duplication", "message": "duplicated call"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state(content=content, start_line=1, end_line=3))

    assert result["findings"][0].start_line == 0


def test_review_quality_keeps_a_line_its_echo_corroborates():
    """Ambiguity only matters when a line would have to be picked FOR
    the model. Here the claimed line is itself one of the matches, so
    the claim is corroborated and there is nothing to resolve — the
    duplicate elsewhere is irrelevant.
    """
    content = "x = compute()\ny = 1\nx = compute()\n"
    items = [{"line": 3, "code": "x = compute()", "severity": "low",
              "category": "duplication", "message": "duplicated call"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state(content=content, start_line=1, end_line=3))

    assert result["findings"][0].start_line == 3


def test_review_quality_echo_match_ignores_indentation():
    """The model is locating a line, not reproducing it for replacement
    the way the fix agent is, so leading whitespace it didn't copy
    exactly must not cost a correct location.
    """
    items = [{"line": 2, "code": "    return x + 1", "severity": "low",
              "category": "naming", "message": "indented echo"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert result["findings"][0].start_line == 2


def test_review_quality_demotes_everything_from_a_degraded_hunk():
    """build_hunks falls back to patch-only context (start_line/end_line
    0) when a file's content fetch fails. There are no file line numbers
    to verify an echo against, so nothing can be placed from it.
    """
    items = [{"line": 1, "code": "def f(x):", "severity": "low",
              "category": "naming", "message": "degraded"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state(start_line=0, end_line=0))

    assert result["findings"][0].start_line == 0
    assert result["findings"][0].message == "degraded"


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
    hits = {("a.py", "abc123", generative_cache_agent("test")): CachedAgentResult(findings=[cached_finding])}

    with patch("codeguard.pipeline.nodes.call_agent") as mock_call:
        result = review_test(_hunk_state() | {"hunk_cache_hits": hits})

    mock_call.assert_not_called()
    assert result["findings"] == [cached_finding]


# --- Noise budget (Quality/Test are the only ungrounded agents) ---

def test_review_quality_parses_confidence_field():
    items = [{"line": 1, "code": "def f(x):", "severity": "low", "category": "naming", "message": "x", "confidence": 0.4}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert result["findings"][0].confidence == 0.4


def test_review_quality_missing_confidence_defaults_to_1():
    items = [{"line": 1, "code": "def f(x):", "severity": "low", "category": "naming", "message": "x"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert result["findings"][0].confidence == 1.0


def test_review_quality_clamps_confidence_into_0_1_range():
    items = [{"line": 1, "code": "def f(x):", "severity": "low", "category": "naming", "message": "a", "confidence": 5.0}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert result["findings"][0].confidence == 1.0


def test_review_quality_clamps_severity_to_settings_max_severity():
    """An LLM's own opinion is never HIGH/CRITICAL, no matter what it
    reports — settings.quality_test_max_severity defaults to MEDIUM."""
    items = [{"line": 1, "code": "def f(x):", "severity": "critical", "category": "structure", "message": "x"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    assert result["findings"][0].severity == Severity.MEDIUM


def test_review_quality_caps_findings_per_hunk_keeping_the_most_severe_and_confident():
    items = [
        {"line": 1, "code": "def f(x):", "severity": "low", "category": "naming", "message": "1", "confidence": 0.9},
        {"line": 1, "code": "def f(x):", "severity": "medium", "category": "naming", "message": "2", "confidence": 0.9},
        {"line": 1, "code": "def f(x):", "severity": "low", "category": "naming", "message": "3", "confidence": 0.1},
        {"line": 1, "code": "def f(x):", "severity": "low", "category": "naming", "message": "4", "confidence": 0.5},
        {"line": 1, "code": "def f(x):", "severity": "low", "category": "naming", "message": "5", "confidence": 0.6},
    ]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = review_quality(_hunk_state())

    findings = result["findings"]
    assert len(findings) == 3  # default noise budget cap
    messages = {f.message for f in findings}
    assert messages == {"2", "1", "5"}  # medium first, then the two highest-confidence lows


# --- Found via the live adversarial/dogfood runs ---

def test_review_quality_parses_a_fenced_response_with_trailing_prose():
    """Real raw model output captured during a live adversarial
    run: the model wraps its answer in a ```json fence and then explains
    itself in prose afterward, despite being told to respond with ONLY
    the JSON array. The old parser only stripped a fence around the
    ENTIRE response and failed outright on this — see nodes.py's
    _JSON_FENCE_RE docstring."""
    raw_text = (
        '```json\n'
        '[{"line": 1, "code": "def f(x):", "severity": "low", "category": "naming", "message": "single-letter names", "confidence": 0.8}]\n'
        '```\n\n'
        'The hunk contains a simple function. The comments appear to be placeholder/removed content '
        'markers, but they do not affect the actual code logic.'
    )

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_raw_result(raw_text)):
        result = review_quality(_hunk_state())

    assert len(result["findings"]) == 1
    assert result["findings"][0].message == "single-letter names"


def test_review_quality_parses_a_fenced_empty_array_with_trailing_prose():
    raw_text = '```json\n[]\n```\n\nNo real issues here, just an explanation the model added anyway.'

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_raw_result(raw_text)):
        result = review_quality(_hunk_state())

    assert result["findings"] == []


def test_review_quality_pins_temperature_to_zero():
    """Found live: quality-agent's own category label for the same hunk
    flipped between runs (quality.complexity / quality.structure / not
    flagged at all) — traced to no call anywhere pinning temperature,
    so every call ran at the API's own default (1.0), not 0."""
    items = [{"line": 1, "code": "def f(x):", "severity": "low", "category": "naming", "message": "x"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)) as mock_call:
        review_quality(_hunk_state())

    assert mock_call.call_args.kwargs["temperature"] == 0
