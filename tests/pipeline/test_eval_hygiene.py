"""Regression coverage for review_eval_hygiene's own heuristics — a pure
function over an already-fetched base-tree file map, tested directly
with no GitHub calls (codeguard/github/base_tree.py's fetch is what
talks to GitHub; not exercised here).
"""

from __future__ import annotations

from codeguard.pipeline.eval_hygiene import review_eval_hygiene


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def test_empty_base_tree_produces_no_findings():
    assert review_eval_hygiene({}) == []


def test_llm_calls_with_no_evals_and_no_output_asserting_tests_is_flagged():
    files = {
        "app/assistant.py": "import anthropic\nclient = anthropic.Anthropic()\n",
    }
    findings = review_eval_hygiene(files)
    assert "eval-hygiene.missing-evals" in _rule_ids(findings)


def test_llm_calls_with_evals_dir_present_is_not_flagged():
    files = {
        "app/assistant.py": "import anthropic\nclient = anthropic.Anthropic()\n",
        "evals/fixture_01.py": "expected = {}\n",
    }
    findings = review_eval_hygiene(files)
    assert "eval-hygiene.missing-evals" not in _rule_ids(findings)


def test_llm_calls_with_output_asserting_test_is_not_flagged():
    files = {
        "app/assistant.py": "import anthropic\nclient = anthropic.Anthropic()\n",
        "tests/test_assistant.py": "import anthropic\ndef test_x():\n    assert True\n",
    }
    findings = review_eval_hygiene(files)
    assert "eval-hygiene.missing-evals" not in _rule_ids(findings)


def test_non_ai_repo_produces_no_missing_evals_finding():
    files = {"app/main.py": "def add(a, b):\n    return a + b\n"}
    findings = review_eval_hygiene(files)
    assert "eval-hygiene.missing-evals" not in _rule_ids(findings)


def test_test_calling_live_llm_api_with_no_mock_marker_is_flagged():
    files = {
        "tests/test_assistant.py": (
            "import anthropic\n"
            "def test_live():\n"
            "    client = anthropic.Anthropic()\n"
            "    resp = client.messages.create(model='x', messages=[])\n"
            "    assert resp\n"
        ),
    }
    findings = review_eval_hygiene(files)
    assert "eval-hygiene.live-llm-calls-in-tests" in _rule_ids(findings)


def test_test_with_mock_marker_is_not_flagged_as_live():
    files = {
        "tests/test_assistant.py": (
            "from unittest.mock import Mock\n"
            "import anthropic\n"
            "def test_mocked():\n"
            "    client = Mock()\n"
            "    assert client\n"
        ),
    }
    findings = review_eval_hygiene(files)
    assert "eval-hygiene.live-llm-calls-in-tests" not in _rule_ids(findings)


def test_long_inline_prompt_with_no_prompts_dir_is_flagged():
    long_prompt = "x" * 250
    files = {
        "app/assistant.py": (
            "import anthropic\n"
            "client = anthropic.Anthropic()\n"
            "client.messages.create(model='x', system=\"\"\"" + long_prompt + "\"\"\", messages=[])\n"
        ),
    }
    findings = review_eval_hygiene(files)
    assert "eval-hygiene.unversioned-inline-prompts" in _rule_ids(findings)


def test_long_inline_prompt_with_prompts_dir_present_is_not_flagged():
    long_prompt = "x" * 250
    files = {
        "app/assistant.py": (
            "import anthropic\n"
            "client = anthropic.Anthropic()\n"
            "client.messages.create(model='x', system=\"\"\"" + long_prompt + "\"\"\", messages=[])\n"
        ),
        "prompts/assistant.md": "You are a helpful assistant.",
    }
    findings = review_eval_hygiene(files)
    assert "eval-hygiene.unversioned-inline-prompts" not in _rule_ids(findings)


def test_short_inline_string_is_not_flagged_as_a_prompt():
    files = {
        "app/assistant.py": (
            "import anthropic\n"
            "client = anthropic.Anthropic()\n"
            "client.messages.create(model='x', system=\"short\", messages=[])\n"
        ),
    }
    findings = review_eval_hygiene(files)
    assert "eval-hygiene.unversioned-inline-prompts" not in _rule_ids(findings)
