"""The verdict contract's optional per-line notes and structured fields.

ONE confirm/dismiss per rule_id stays exactly as it was. What changes is
what a confirmed verdict MAY carry:

  lines   {"<line>": "<one sentence about THAT line>"}. Without it, one
          message was copied onto every occurrence, so db.py:13, :20 and
          :29 each repeated the same three-function paragraph and the
          timeout finding at :33 described :46 as well.
  title / what / why / fix
          the structured audit page's card. Optional, each falls back.

Backward compatibility is the first test: a response with none of the new
keys must produce exactly what it produced before.
"""

from __future__ import annotations

import json
import secrets
import string
from unittest.mock import patch

from codeguard.pipeline import nodes
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.models import CachedAgentResult, DismissedFinding
from codeguard.pipeline.nodes import compute_cache_keys, review_ai_aware, review_security
from tests.pipeline.conftest import make_finding

CONTENT = "\n".join(f"line {i}" for i in range(1, 60)) + "\n"


def _result(items) -> AgentCallResult:
    return AgentCallResult(raw_text=json.dumps(items), tokens_in=10, tokens_out=5,
                           estimated_cost_usd=0.001, latency_s=0.01)


def _state(findings, content=CONTENT, cache=None) -> dict:
    return {"owner": "o", "repo": "r", "path": "app.py", "content": content,
            "patch": "", "findings": findings, "hunk_cache_hits": cache or {}}


def _timeouts():
    return [
        make_finding(file="app.py", line=33, tool="semgrep", rule_id="llm-call-missing-timeout"),
        make_finding(file="app.py", line=46, tool="semgrep", rule_id="llm-call-missing-timeout"),
    ]


def test_a_response_without_the_new_keys_is_read_exactly_as_before():
    items = [{"rule_id": "llm-call-missing-timeout", "verdict": "confirmed",
              "severity": "medium", "message": "No timeout on either call."}]
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(items)):
        out = review_ai_aware(_state(_timeouts()))

    assert [f.message for f in out["findings"]] == ["No timeout on either call."] * 2
    assert all(f.what == "" and f.why == "" and f.fix == "" and f.title == "" for f in out["findings"])


def test_each_occurrence_gets_only_its_own_lines_note():
    items = [{
        "rule_id": "llm-call-missing-timeout", "verdict": "confirmed", "severity": "medium",
        "message": "Calls have no timeout.",
        "lines": {"33": "summarize() calls the API with no timeout.",
                  "46": "classify() calls the API with no timeout."},
        "fix": "Pass timeout= to create().",
    }]
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(items)):
        out = review_ai_aware(_state(_timeouts()))

    by_line = {f.start_line: f for f in out["findings"]}
    assert "summarize()" in by_line[33].message and "classify()" not in by_line[33].message
    assert "classify()" in by_line[46].message and "summarize()" not in by_line[46].message
    assert by_line[33].what == "summarize() calls the API with no timeout."
    assert by_line[33].fix == by_line[46].fix == "Pass timeout= to create()."


def test_a_line_the_notes_omit_falls_back_to_the_shared_text():
    items = [{
        "rule_id": "llm-call-missing-timeout", "verdict": "confirmed", "severity": "medium",
        "message": "Calls have no timeout.", "what": "No timeout is set.",
        "lines": {"33": "summarize() calls the API with no timeout."},
    }]
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(items)):
        out = review_ai_aware(_state(_timeouts()))

    by_line = {f.start_line: f for f in out["findings"]}
    assert by_line[46].what == "No timeout is set."
    assert "summarize()" not in by_line[46].message


def test_structured_fields_are_carried_and_redacted():
    key = "sk-ant-api03-" + "".join(secrets.choice(string.ascii_letters) for _ in range(60))
    items = [{
        "rule_id": "B608", "verdict": "confirmed", "severity": "high",
        "message": "SQL built by string formatting.",
        "title": "SQL injection via % formatting",
        "what": "The email is %-formatted into the query.",
        "why": "An email like ' OR '1'='1 returns every user.",
        "fix": f"Use a placeholder. (not {key})",
    }]
    finding = make_finding(file="app.py", line=13, tool="bandit", rule_id="B608")
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(items)):
        out = review_security(_state([finding]))

    f = out["findings"][0]
    assert f.title == "SQL injection via % formatting"
    assert f.why.startswith("An email like")
    assert key not in f.fix


def test_malformed_extras_are_ignored_not_fatal():
    items = [{
        "rule_id": "llm-call-missing-timeout", "verdict": "confirmed", "severity": "medium",
        "message": "Calls have no timeout.", "lines": ["not", "a", "dict"], "what": 7,
    }]
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(items)):
        out = review_ai_aware(_state(_timeouts()))

    assert [f.message for f in out["findings"]] == ["Calls have no timeout."] * 2


def test_one_verdict_per_rule_id_is_still_the_contract():
    prompt = nodes._VERDICT_CONTRACT
    assert "exactly ONE verdict per DISTINCT rule_id" in prompt
    assert '"lines"' in prompt and "optional" in prompt.lower()
    for key in ('"title"', '"what"', '"why"', '"fix"'):
        assert key in prompt


def test_the_prompt_says_comments_never_decide_a_credential_verdict():
    prompt = nodes._VERDICT_CONTRACT.lower()
    assert "placeholder-like" in prompt and "high-entropy" in prompt
    assert "never a comment" in prompt


def test_verdict_cache_keys_are_versioned():
    """The contract changed, so a verdict cached under the old one --
    including the playground's comment-based key dismissals -- must not
    be served for an unchanged file."""
    finding = make_finding(file="app.py", line=1, tool="bandit", rule_id="B105")
    keys = compute_cache_keys({"app.py": "import anthropic\n"}, {"app.py": ""}, [finding], True)
    agents = {k[2] for k in keys}
    assert nodes.verdict_cache_agent("security") in agents
    assert nodes.verdict_cache_agent("ai_aware") in agents
    assert "security" not in agents and "ai_aware" not in agents


def test_the_credential_guard_runs_on_a_cache_hit_too():
    secret = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(40))
    content = f'DB_PASSWORD = "{secret}"  # fake\n'
    finding = make_finding(file="app.py", line=1, tool="bandit", rule_id="B105")
    cached = CachedAgentResult(
        findings=[], dismissed=[DismissedFinding(file="app.py", start_line=1, rule_id="B105", reason="comment says fake")],
    )
    key = ("app.py", nodes.hash_content(content), nodes.verdict_cache_agent("security"))

    with patch("codeguard.pipeline.nodes.call_agent") as call:
        out = review_security(_state([finding], content=content, cache={key: cached}))

    call.assert_not_called()
    assert [f.rule_id for f in out["findings"]] == ["B105"]
    assert out["dismissed_findings"] == []


def test_a_confirmed_verdict_with_structure_but_no_message_is_still_a_verdict():
    """Seen live, 3 runs of 3 on fixture_02: given the optional fields,
    the model filled title/what/why/fix and left `message` out -- and a
    confirmed verdict without one was "malformed", so the agent's verdict
    was thrown away for the raw finding. The structure IS the message."""
    items = [{
        "rule_id": "llm-call-missing-timeout", "verdict": "confirmed", "severity": "medium",
        "title": "No timeout", "what": "The call has no timeout.",
        "why": "A hung connection blocks forever.", "fix": "Pass timeout=.",
    }]
    finding = make_finding(file="app.py", line=33, tool="semgrep", rule_id="llm-call-missing-timeout")
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(items)):
        out = review_ai_aware(_state([finding]))

    f = out["findings"][0]
    assert f.source_tool == "ai_aware", "the agent's verdict, not the raw finding"
    assert f.message == "The call has no timeout. A hung connection blocks forever. Pass timeout=."
    assert f.title == "No timeout"


def test_the_contract_says_message_is_required_even_with_structure():
    assert "always include \"message\"" in nodes._VERDICT_CONTRACT
