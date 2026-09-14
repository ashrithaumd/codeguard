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

from codeguard.config import RepoConfig
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


def test_review_ai_aware_parses_model_output_into_findings_and_tracks_cost():
    finding = make_finding(file="app/assistant.py", rule_id="llm-call-missing-max-tokens", tool="semgrep")
    model_items = [{
        "start_line": 7, "end_line": 7, "severity": "high",
        "rule_id": "llm-call-missing-max-tokens",
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
    assert result["tokens_in"] == 100
    assert result["tokens_out"] == 50
    assert result["estimated_cost_usd"] > 0
    assert result["node_latencies"][0]["node"] == "review_ai_aware"


def test_review_ai_aware_backfills_a_finding_the_model_silently_dropped():
    """LLM non-determinism means the system prompt's "never silently
    drop a finding" instruction isn't a guarantee on its own — observed
    directly during Phase 6 live verification. review_ai_aware must
    never leave a PR with strictly less coverage than raw Semgrep alone.
    """
    kept = make_finding(file="app/assistant.py", rule_id="llm-call-missing-max-tokens", tool="semgrep")
    dropped = make_finding(file="app/assistant.py", rule_id="llm-unpinned-model-alias", tool="semgrep")
    model_items = [{
        "start_line": 7, "end_line": 7, "severity": "high",
        "rule_id": "llm-call-missing-max-tokens", "message": "no max_tokens set.",
    }]

    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = _fake_response(model_items)
        result = review_ai_aware(_file_state(findings=[kept, dropped]))

    rule_ids = {f.rule_id for f in result["findings"]}
    assert rule_ids == {"llm-call-missing-max-tokens", "llm-unpinned-model-alias"}
    # the backfilled one is the original raw Semgrep Finding, untouched
    assert dropped in result["findings"]


def test_review_ai_aware_empty_array_on_nonempty_input_falls_back_via_coverage_guard():
    """The system prompt requires every input finding to produce an
    output object (even a low-severity "not a real issue" one) — a
    genuinely empty array for non-empty input means the model dropped
    everything with no explanation, which _ensure_full_coverage treats
    the same as any other dropped finding: fall back to raw Semgrep.
    """
    finding = make_finding(file="app/assistant.py")
    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = _fake_response([])
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == [finding]


def test_review_ai_aware_falls_back_to_raw_findings_on_api_failure():
    finding = make_finding(file="app/assistant.py")
    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.side_effect = RuntimeError("boom")
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == [finding]
    assert "tokens_in" not in result  # no usage to report — the call never returned


def test_review_ai_aware_falls_back_on_unparseable_output():
    finding = make_finding(file="app/assistant.py")
    with patch("codeguard.pipeline.nodes.anthropic.Anthropic") as mock_client_cls:
        mock_client_cls.return_value.messages.create.return_value = SimpleNamespace(
            content=[SimpleNamespace(text="not json")],
            usage=SimpleNamespace(input_tokens=10, output_tokens=5),
        )
        result = review_ai_aware(_file_state(findings=[finding]))

    assert result["findings"] == [finding]


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
