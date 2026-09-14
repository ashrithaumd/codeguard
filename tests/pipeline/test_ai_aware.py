"""Regression coverage for review_ai_aware and its routing. The
Anthropic SDK call itself is mocked (patch
codeguard.pipeline.nodes.anthropic.Anthropic) — same "no live network
calls" bar the rest of tests/pipeline/ holds itself to; the eval
harness (evals/run_eval.py) is what exercises the real API.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from codeguard.config import RepoConfig, get_settings
from codeguard.pipeline.nodes import review_ai_aware, route_to_ai_aware_reviews, route_to_file_reviews
from codeguard.severity import Severity
from tests.pipeline.conftest import make_finding


def _fake_response(items, tokens_in=100, tokens_out=50):
    return SimpleNamespace(
        content=[SimpleNamespace(text=json.dumps(items))],
        usage=SimpleNamespace(input_tokens=tokens_in, output_tokens=tokens_out),
    )


def _file_state(path="app/assistant.py", content="import anthropic\n", findings=None):
    return {
        "owner": "o", "repo": "r", "path": path, "content": content,
        "patch": "", "findings": findings or [],
    }


def test_review_ai_aware_skips_the_api_call_when_no_findings():
    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        result = review_ai_aware(_file_state(findings=[]))

    mock_client_cls.assert_not_called()
    assert result == {}


def test_review_ai_aware_confirmed_verdict_produces_a_finding_and_tracks_cost():
    finding = make_finding(file="app/assistant.py", rule_id="llm-call-missing-max-tokens", tool="semgrep")
    model_items = [{
        "rule_id": "llm-call-missing-max-tokens", "verdict": "confirmed", "severity": "high",
        "message": "no max_tokens set; bounded response size needed.",
    }]

    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = _fake_response(model_items)
        result = review_ai_aware(_file_state(findings=[finding]))

    assert len(result["findings"]) == 1
    out = result["findings"][0]
    assert out.severity == Severity.HIGH
    assert out.source_tool == "ai-aware"
    assert out.rule_id == "llm-call-missing-max-tokens"
    assert out.start_line == finding.start_line  # location always comes from the raw finding
    assert result["dismissed_findings"] == []
    assert result["tokens_in"] == 100
    assert result["tokens_out"] == 50
    assert result["estimated_cost_usd"] > 0
    assert result["node_latencies"][0]["node"] == "review_ai_aware"


def test_review_ai_aware_confirmed_verdict_applies_to_every_occurrence_of_the_rule_id():
    """One verdict per distinct rule_id (Phase 6.1's contract) still
    must cover every raw occurrence of that rule_id in the file, each
    keeping its own line — not just the first one.
    """
    first = make_finding(file="app/assistant.py", line=7, rule_id="llm-unpinned-model-alias", tool="semgrep")
    second = make_finding(file="app/assistant.py", line=15, rule_id="llm-unpinned-model-alias", tool="semgrep")
    model_items = [{"rule_id": "llm-unpinned-model-alias", "verdict": "confirmed", "severity": "medium", "message": "floating alias"}]

    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = _fake_response(model_items)
        result = review_ai_aware(_file_state(findings=[first, second]))

    lines = sorted(f.start_line for f in result["findings"])
    assert lines == [7, 15]
    assert all(f.source_tool == "ai-aware" for f in result["findings"])


def test_review_ai_aware_dismissed_verdict_is_recorded_and_not_posted_inline():
    finding = make_finding(file="app/assistant.py", rule_id="llm-unpinned-model-alias", tool="semgrep")
    model_items = [{
        "rule_id": "llm-unpinned-model-alias", "verdict": "dismissed",
        "message": "this string is a pinned internal proxy alias, not a floating upstream one — see config.py's ALIAS_MAP.",
    }]

    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = _fake_response(model_items)
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == []
    assert len(result["dismissed_findings"]) == 1
    dismissal = result["dismissed_findings"][0]
    assert dismissal.rule_id == "llm-unpinned-model-alias"
    assert dismissal.file == "app/assistant.py"
    assert "ALIAS_MAP" in dismissal.reason


def test_review_ai_aware_fail_safe_mode_ignores_dismissals():
    """Settings.ai_aware_dismissals_enabled=False: a dismissal verdict
    is treated as unaddressed, so the coverage fallback backfills the
    raw Semgrep finding as confirmed instead of trusting the model's
    judgment to skip it.
    """
    finding = make_finding(file="app/assistant.py", rule_id="llm-unpinned-model-alias", tool="semgrep")
    model_items = [{"rule_id": "llm-unpinned-model-alias", "verdict": "dismissed", "message": "pinned internally"}]
    fail_safe_settings = get_settings().model_copy(update={"ai_aware_dismissals_enabled": False})

    with patch("codeguard.pipeline.nodes.get_settings", return_value=fail_safe_settings), \
         patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = _fake_response(model_items)
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == [finding]
    assert result["dismissed_findings"] == []


def test_review_ai_aware_backfills_a_rule_id_the_model_left_unaddressed():
    """LLM non-determinism means the system prompt's "address every
    rule_id" instruction isn't a guarantee on its own — observed
    directly during Phase 6 live verification. review_ai_aware must
    never leave a PR with strictly less coverage than raw Semgrep alone.
    """
    kept = make_finding(file="app/assistant.py", rule_id="llm-call-missing-max-tokens", tool="semgrep")
    dropped = make_finding(file="app/assistant.py", rule_id="llm-unpinned-model-alias", tool="semgrep")
    model_items = [{"rule_id": "llm-call-missing-max-tokens", "verdict": "confirmed", "severity": "high", "message": "no max_tokens set."}]

    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = _fake_response(model_items)
        result = review_ai_aware(_file_state(findings=[kept, dropped]))

    rule_ids = {f.rule_id for f in result["findings"]}
    assert rule_ids == {"llm-call-missing-max-tokens", "llm-unpinned-model-alias"}
    # the backfilled one is the original raw Semgrep Finding, untouched
    assert dropped in result["findings"]
    assert result["dismissed_findings"] == []


def test_review_ai_aware_empty_array_on_nonempty_input_falls_back_to_confirmed():
    """A genuinely empty array for non-empty input means the model
    addressed nothing — every input rule_id is unaddressed, so all of
    them fall back to raw Semgrep findings, confirmed.
    """
    finding = make_finding(file="app/assistant.py")
    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = _fake_response([])
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == [finding]
    assert result["dismissed_findings"] == []


def test_review_ai_aware_unknown_rule_id_from_model_is_ignored_not_trusted():
    finding = make_finding(file="app/assistant.py", rule_id="llm-call-missing-max-tokens", tool="semgrep")
    model_items = [{"rule_id": "not-a-real-rule-id", "verdict": "dismissed", "message": "hallucinated"}]

    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = _fake_response(model_items)
        result = review_ai_aware(_file_state(findings=[finding]))

    # the real rule_id was never addressed by a valid verdict, so it's backfilled
    assert result["findings"] == [finding]


def test_review_ai_aware_falls_back_to_raw_findings_on_api_failure():
    finding = make_finding(file="app/assistant.py")
    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.side_effect = RuntimeError("boom")
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == [finding]
    assert "tokens_in" not in result  # no usage to report — the call never returned
    assert "dismissed_findings" not in result


def test_review_ai_aware_falls_back_on_unparseable_output():
    finding = make_finding(file="app/assistant.py")
    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = SimpleNamespace(
            content=[SimpleNamespace(text="not json")],
            usage=SimpleNamespace(input_tokens=10, output_tokens=5),
        )
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == [finding]
    assert result["dismissed_findings"] == []


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


def test_route_to_file_reviews_withholds_semgrep_findings_for_ai_touching_files():
    semgrep_finding = make_finding(file="app/assistant.py", tool="semgrep", rule_id="llm-unpinned-model-alias")
    bandit_finding = make_finding(file="app/assistant.py", tool="bandit", rule_id="B105")
    state = {
        "repo_config": RepoConfig(),
        "owner": "o", "repo": "r",
        "files": {"app/assistant.py": "import anthropic\n"},
        "patches": {},
        "tool_findings": [semgrep_finding, bandit_finding],
    }

    sends = route_to_file_reviews(state)

    assert len(sends) == 1
    forwarded_tools = {f.source_tool for f in sends[0].arg["findings"]}
    assert forwarded_tools == {"bandit"}  # semgrep withheld for review_ai_aware, bandit still flows through


def test_route_to_file_reviews_keeps_semgrep_findings_for_non_ai_files():
    semgrep_finding = make_finding(file="app/plain.py", tool="semgrep", rule_id="some-rule")
    state = {
        "repo_config": RepoConfig(),
        "owner": "o", "repo": "r",
        "files": {"app/plain.py": "def add(a, b):\n    return a + b\n"},
        "patches": {},
        "tool_findings": [semgrep_finding],
    }

    sends = route_to_file_reviews(state)

    assert len(sends) == 1
    assert sends[0].arg["findings"] == [semgrep_finding]
