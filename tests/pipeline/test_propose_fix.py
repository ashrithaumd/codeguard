"""Regression coverage for propose_fix and route_after_fanin's dual
role (plain "summarize" string vs a list[Send] fan-out to propose_fix,
from the same router — confirmed to actually work in LangGraph via a
standalone smoke test, not just assumed).

Every suggestion here carries an `original` echo, because propose_fix
now verifies that the text the fix agent says it is replacing really is
what stands at the finding's own line. See
tests/pipeline/test_fix_suggestion_targeting.py for why.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from langgraph.types import Send

from codeguard.config import RepoConfig
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.nodes import propose_fix, route_after_fanin
from codeguard.severity import Severity
from tests.pipeline.conftest import make_finding


def _fake_result(items):
    return AgentCallResult(raw_text=json.dumps(items), tokens_in=20, tokens_out=10, estimated_cost_usd=0.002, latency_s=0.02)


def test_route_after_fanin_returns_summarize_when_nothing_qualifies():
    state = {
        "findings": [make_finding(severity=Severity.LOW)], "repo_level_findings": [],
        "repo_config": RepoConfig(fix_threshold=Severity.HIGH), "files": {"a.py": "x"}, "owner": "o", "repo": "r",
        "suppressed_fingerprints": frozenset(),
    }

    assert route_after_fanin(state) == "summarize"


def test_route_after_fanin_dispatches_one_send_per_qualifying_file():
    high_a = make_finding(file="a.py", severity=Severity.HIGH)
    high_b = make_finding(file="b.py", severity=Severity.CRITICAL)
    low_c = make_finding(file="c.py", severity=Severity.LOW)
    state = {
        "findings": [high_a, high_b, low_c], "repo_level_findings": [],
        "repo_config": RepoConfig(fix_threshold=Severity.HIGH),
        "files": {"a.py": "x", "b.py": "y", "c.py": "z"}, "patches": {}, "owner": "o", "repo": "r",
        "suppressed_fingerprints": frozenset(),
    }

    result = route_after_fanin(state)

    assert isinstance(result, list) and all(isinstance(s, Send) for s in result)
    paths = {s.arg["path"] for s in result}
    assert paths == {"a.py", "b.py"}  # c.py's LOW finding doesn't qualify


def test_propose_fix_correlates_suggestion_by_fingerprint():
    finding = make_finding(file="a.py", rule_id="B105", line=3, message="hardcoded secret")
    # `original` must be the real text at the finding's line — propose_fix
    # now verifies the fix agent is replacing the code it claims to be.
    content = "import os\n\nPASSWORD = 'hunter2'\n"
    items = [{
        "fingerprint": finding.fingerprint,
        "original": "PASSWORD = 'hunter2'",
        "replacement": 'PASSWORD = os.environ["PASSWORD"]',
    }]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = propose_fix({
            "owner": "o", "repo": "r", "path": "a.py", "content": content,
            "findings": [finding],
        })

    assert result["should_fix"] is True
    assert len(result["fix_suggestions"]) == 1
    suggestion = result["fix_suggestions"][0]
    assert suggestion.fingerprint == finding.fingerprint
    assert suggestion.suggestion_body.startswith("```suggestion\n")
    assert "PASSWORD" in suggestion.suggestion_body


def test_propose_fix_ignores_a_suggestion_for_an_unknown_fingerprint():
    finding = make_finding(file="a.py", rule_id="B105")
    items = [{"fingerprint": "not-a-real-fingerprint", "replacement": "x = 1"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = propose_fix({"owner": "o", "repo": "r", "path": "a.py", "content": "x\n", "findings": [finding]})

    assert result["fix_suggestions"] == []


def test_propose_fix_call_failure_still_marks_should_fix():
    finding = make_finding(file="a.py", rule_id="B105")
    with patch("codeguard.pipeline.nodes.call_agent", return_value=AgentCallResult(raw_text=None, error="boom")):
        result = propose_fix({"owner": "o", "repo": "r", "path": "a.py", "content": "x\n", "findings": [finding]})

    assert result["should_fix"] is True
    assert "fix_suggestions" not in result


def test_route_after_fanin_excludes_a_suppressed_fingerprint():
    """A suppressed fingerprint doesn't qualify for a fix
    suggestion even if its severity would otherwise meet fix_threshold."""
    suppressed = make_finding(file="a.py", severity=Severity.CRITICAL)
    state = {
        "findings": [suppressed], "repo_level_findings": [],
        "repo_config": RepoConfig(fix_threshold=Severity.HIGH),
        "files": {"a.py": "x"}, "patches": {}, "owner": "o", "repo": "r",
        "suppressed_fingerprints": frozenset({suppressed.fingerprint}),
    }

    assert route_after_fanin(state) == "summarize"


def test_propose_fix_drops_a_suggestion_for_a_line_outside_the_diff():
    """GitHub's suggestion-block API can only attach to a diff
    line — a suggestion for an unchanged line is dropped, but the
    finding itself is untouched (still reported elsewhere)."""
    finding = make_finding(file="a.py", rule_id="B105", line=50, message="hardcoded secret")
    items = [{"fingerprint": finding.fingerprint, "replacement": "x = 1"}]
    patch_text = "@@ -1,5 +1,5 @@\n context"  # only lines 1-5 are in the diff; line 50 is not

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = propose_fix({
            "owner": "o", "repo": "r", "path": "a.py", "content": "x\n" * 60,
            "findings": [finding], "patch": patch_text,
        })

    assert result["fix_suggestions"] == []


def test_propose_fix_keeps_a_suggestion_for_a_line_inside_the_diff():
    finding = make_finding(file="a.py", rule_id="B105", line=3, message="hardcoded secret")
    items = [{"fingerprint": finding.fingerprint, "original": "x", "replacement": "x = 1"}]
    patch_text = "@@ -1,5 +1,5 @@\n context"

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = propose_fix({
            "owner": "o", "repo": "r", "path": "a.py", "content": "x\n" * 10,
            "findings": [finding], "patch": patch_text,
        })

    assert len(result["fix_suggestions"]) == 1


def test_propose_fix_drops_a_suggestion_whose_finding_targets_a_different_file():
    """Defense-in-depth: route_after_fanin already guarantees every
    finding passed to one propose_fix branch shares that branch's own
    path, but a suggestion is still verified against state["path"]
    directly rather than trusted implicitly."""
    finding = make_finding(file="other.py", rule_id="B105", line=1, message="hardcoded secret")
    items = [{"fingerprint": finding.fingerprint, "replacement": "x = 1"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)):
        result = propose_fix({"owner": "o", "repo": "r", "path": "a.py", "content": "x\n", "findings": [finding]})

    assert result["fix_suggestions"] == []


def test_propose_fix_pins_temperature_to_zero():
    """A fix suggestion should be the same correct patch every time, not
    one of several plausible random ones — pinned for the same reason
    as the verdict-contract and Quality/Test agents."""
    finding = make_finding(file="a.py", rule_id="B105", line=1, message="hardcoded secret")
    items = [{"fingerprint": finding.fingerprint, "replacement": "x = 1"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(items)) as mock_call:
        propose_fix({"owner": "o", "repo": "r", "path": "a.py", "content": "x\n", "findings": [finding]})

    assert mock_call.call_args.kwargs["temperature"] == 0
