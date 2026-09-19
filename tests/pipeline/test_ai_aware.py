"""Regression coverage for review_ai_aware and its routing. The actual
Anthropic call lives behind codeguard.pipeline.llm_call's call_agent —
mocked here directly (not anthropic.Anthropic three layers down), same
"no live network calls" bar the rest of
tests/pipeline/ holds itself to; the eval harness (evals/run_eval.py)
is what exercises the real API. review_security shares the exact same
_run_verdict_agent/_apply_verdicts machinery — see
tests/pipeline/test_security_agent.py for its own routing/hunk-cache
coverage, not duplicated here.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from codeguard.config import RepoConfig, get_settings
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.nodes import review_ai_aware, route_to_ai_aware_reviews, route_to_file_reviews
from codeguard.severity import Severity
from tests.pipeline.conftest import make_finding


def _fake_result(items, tokens_in=100, tokens_out=50):
    return AgentCallResult(raw_text=json.dumps(items), tokens_in=tokens_in, tokens_out=tokens_out, estimated_cost_usd=0.001, latency_s=0.01)


def _file_state(path="app/assistant.py", content="import anthropic\n", findings=None):
    return {
        "owner": "o", "repo": "r", "path": path, "content": content,
        "patch": "", "findings": findings or [], "hunk_cache_hits": {},
    }


def test_review_ai_aware_skips_the_api_call_when_no_findings():
    with patch("codeguard.pipeline.nodes.call_agent") as mock_call:
        result = review_ai_aware(_file_state(findings=[]))

    mock_call.assert_not_called()
    assert result == {}


def test_review_ai_aware_confirmed_verdict_produces_a_finding_and_tracks_cost():
    finding = make_finding(file="app/assistant.py", rule_id="llm-call-missing-max-tokens", tool="semgrep")
    model_items = [{
        "rule_id": "llm-call-missing-max-tokens", "verdict": "confirmed", "severity": "high",
        "message": "no max_tokens set; bounded response size needed.",
    }]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)):
        result = review_ai_aware(_file_state(findings=[finding]))

    assert len(result["findings"]) == 1
    out = result["findings"][0]
    assert out.severity == Severity.HIGH
    assert out.source_tool == "ai_aware"
    assert out.rule_id == "llm-call-missing-max-tokens"
    assert out.start_line == finding.start_line  # location always comes from the raw finding
    assert result["dismissed_findings"] == []
    assert result["tokens_in"] == 100
    assert result["tokens_out"] == 50
    assert result["estimated_cost_usd"] > 0
    assert result["node_latencies"][0]["node"] == "review_ai_aware"
    assert len(result["cache_writes"]) == 1
    assert result["cache_writes"][0].agent == "ai_aware"


def test_review_ai_aware_confirmed_verdict_with_dismissal_language_is_flipped_to_dismissed():
    """Found live on this repo's own CodeGuard review — a model
    can literally answer verdict="confirmed" while its own message says
    "No action needed... this pattern is appropriate for tests." The
    JSON verdict field shouldn't win over what the model's own words say.
    """
    finding = make_finding(file="app/assistant.py", rule_id="B101", tool="bandit")
    model_items = [{
        "rule_id": "B101", "verdict": "confirmed", "severity": "low",
        "message": "Assert statements are standard in test code. No action needed; this pattern is appropriate for tests.",
    }]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)):
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == []
    assert len(result["dismissed_findings"]) == 1
    assert result["dismissed_findings"][0].rule_id == "B101"


def test_review_ai_aware_confirmed_verdict_flip_increments_the_metric():
    from codeguard.pipeline.metrics import verdict_flip_total

    finding = make_finding(file="app/assistant.py", rule_id="B101", tool="bandit")
    model_items = [{"rule_id": "B101", "verdict": "confirmed", "severity": "low", "message": "Not a security risk here."}]
    before = verdict_flip_total.labels(agent="ai_aware")._value.get()

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)):
        review_ai_aware(_file_state(findings=[finding]))

    after = verdict_flip_total.labels(agent="ai_aware")._value.get()
    assert after == before + 1


def test_review_ai_aware_confirmed_verdict_without_dismissal_language_stays_confirmed():
    finding = make_finding(file="app/assistant.py", rule_id="llm-call-missing-max-tokens", tool="semgrep")
    model_items = [{
        "rule_id": "llm-call-missing-max-tokens", "verdict": "confirmed", "severity": "high",
        "message": "no max_tokens set; bounded response size needed.",
    }]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)):
        result = review_ai_aware(_file_state(findings=[finding]))

    assert len(result["findings"]) == 1
    assert result["dismissed_findings"] == []


def test_review_ai_aware_confirmed_verdict_applies_to_every_occurrence_of_the_rule_id():
    first = make_finding(file="app/assistant.py", line=7, rule_id="llm-unpinned-model-alias", tool="semgrep")
    second = make_finding(file="app/assistant.py", line=15, rule_id="llm-unpinned-model-alias", tool="semgrep")
    model_items = [{"rule_id": "llm-unpinned-model-alias", "verdict": "confirmed", "severity": "medium", "message": "floating alias"}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)):
        result = review_ai_aware(_file_state(findings=[first, second]))

    lines = sorted(f.start_line for f in result["findings"])
    assert lines == [7, 15]
    assert all(f.source_tool == "ai_aware" for f in result["findings"])


def test_review_ai_aware_dismissed_verdict_is_recorded_and_not_posted_inline():
    finding = make_finding(file="app/assistant.py", rule_id="llm-unpinned-model-alias", tool="semgrep")
    model_items = [{
        "rule_id": "llm-unpinned-model-alias", "verdict": "dismissed",
        "message": "this string is a pinned internal proxy alias, not a floating upstream one — see config.py's ALIAS_MAP.",
    }]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)):
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == []
    assert len(result["dismissed_findings"]) == 1
    dismissal = result["dismissed_findings"][0]
    assert dismissal.rule_id == "llm-unpinned-model-alias"
    assert dismissal.file == "app/assistant.py"
    assert "ALIAS_MAP" in dismissal.reason


def test_review_ai_aware_fail_safe_mode_ignores_dismissals():
    finding = make_finding(file="app/assistant.py", rule_id="llm-unpinned-model-alias", tool="semgrep")
    model_items = [{"rule_id": "llm-unpinned-model-alias", "verdict": "dismissed", "message": "pinned internally"}]
    fail_safe_settings = get_settings().model_copy(update={"ai_aware_dismissals_enabled": False})

    with patch("codeguard.pipeline.nodes.get_settings", return_value=fail_safe_settings), \
         patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)):
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == [finding]
    assert result["dismissed_findings"] == []


def test_review_ai_aware_backfills_a_rule_id_the_model_left_unaddressed():
    kept = make_finding(file="app/assistant.py", rule_id="llm-call-missing-max-tokens", tool="semgrep")
    dropped = make_finding(file="app/assistant.py", rule_id="llm-unpinned-model-alias", tool="semgrep")
    model_items = [{"rule_id": "llm-call-missing-max-tokens", "verdict": "confirmed", "severity": "high", "message": "no max_tokens set."}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result(model_items)):
        result = review_ai_aware(_file_state(findings=[kept, dropped]))

    rule_ids = {f.rule_id for f in result["findings"]}
    assert rule_ids == {"llm-call-missing-max-tokens", "llm-unpinned-model-alias"}
    assert dropped in result["findings"]
    assert result["dismissed_findings"] == []


def test_review_ai_aware_empty_array_on_nonempty_input_falls_back_to_confirmed():
    finding = make_finding(file="app/assistant.py")
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_fake_result([])):
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == [finding]
    assert result["dismissed_findings"] == []


def test_review_ai_aware_falls_back_to_raw_findings_on_api_failure():
    finding = make_finding(file="app/assistant.py")
    with patch("codeguard.pipeline.nodes.call_agent", return_value=AgentCallResult(raw_text=None, error="boom")):
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == [finding]
    assert "tokens_in" not in result
    assert "dismissed_findings" not in result


def test_review_ai_aware_uses_hunk_cache_hit_and_skips_the_call():
    from codeguard.pipeline.models import CachedAgentResult
    from codeguard.diff.parse import hash_content

    finding = make_finding(file="app/assistant.py", rule_id="llm-unpinned-model-alias", tool="semgrep")
    content = "import anthropic\n"
    cached_finding = make_finding(file="app/assistant.py", rule_id="llm-unpinned-model-alias", tool="ai_aware", message="cached verdict")
    hits = {("app/assistant.py", hash_content(content), "ai_aware"): CachedAgentResult(findings=[cached_finding])}

    with patch("codeguard.pipeline.nodes.call_agent") as mock_call:
        result = review_ai_aware(_file_state(content=content, findings=[finding]) | {"hunk_cache_hits": hits})

    mock_call.assert_not_called()
    assert result["findings"] == [cached_finding]
    assert "cache_writes" not in result


def test_route_to_ai_aware_reviews_only_dispatches_ai_touching_files():
    state = {
        "repo_config": RepoConfig(),
        "owner": "o", "repo": "r",
        "files": {
            "app/assistant.py": "import anthropic\n",
            "app/plain.py": "def add(a, b):\n    return a + b\n",
        },
        "patches": {},
        "tool_findings": [
            make_finding(file="app/assistant.py", tool="semgrep", rule_id="llm-unpinned-model-alias"),
            make_finding(file="app/assistant.py", tool="bandit", rule_id="B105"),
        ],
        "hunk_cache_hits": {},
    }

    sends = route_to_ai_aware_reviews(state)

    assert len(sends) == 1
    assert sends[0].arg["path"] == "app/assistant.py"
    assert [f.source_tool for f in sends[0].arg["findings"]] == ["semgrep"]


def test_route_to_ai_aware_reviews_returns_nothing_when_disabled_in_repo_config():
    state = {
        "repo_config": RepoConfig(enable_ai_aware=False),
        "owner": "o", "repo": "r",
        "files": {"app/assistant.py": "import anthropic\n"},
        "patches": {},
        "tool_findings": [],
    }

    assert route_to_ai_aware_reviews(state) == []


def test_route_to_file_reviews_withholds_semgrep_and_bandit_findings_for_ai_touching_files():
    semgrep_finding = make_finding(file="app/assistant.py", tool="semgrep", rule_id="llm-unpinned-model-alias")
    bandit_finding = make_finding(file="app/assistant.py", tool="bandit", rule_id="B105")
    ruff_finding = make_finding(file="app/assistant.py", tool="ruff", rule_id="E501")
    state = {
        "repo_config": RepoConfig(),
        "owner": "o", "repo": "r",
        "files": {"app/assistant.py": "import anthropic\n"},
        "patches": {},
        "tool_findings": [semgrep_finding, bandit_finding, ruff_finding],
    }

    sends = route_to_file_reviews(state)

    assert len(sends) == 1
    forwarded_tools = {f.source_tool for f in sends[0].arg["findings"]}
    assert forwarded_tools == {"ruff"}  # semgrep -> ai_aware, bandit -> security, ruff flows through


def test_route_to_file_reviews_withholds_only_bandit_for_non_ai_files():
    semgrep_finding = make_finding(file="app/plain.py", tool="semgrep", rule_id="some-rule")
    bandit_finding = make_finding(file="app/plain.py", tool="bandit", rule_id="B105")
    state = {
        "repo_config": RepoConfig(),
        "owner": "o", "repo": "r",
        "files": {"app/plain.py": "def add(a, b):\n    return a + b\n"},
        "patches": {},
        "tool_findings": [semgrep_finding, bandit_finding],
    }

    sends = route_to_file_reviews(state)

    assert len(sends) == 1
    forwarded_tools = {f.source_tool for f in sends[0].arg["findings"]}
    assert forwarded_tools == {"semgrep"}  # bandit withheld for security; semgrep unclaimed on a non-AI file
