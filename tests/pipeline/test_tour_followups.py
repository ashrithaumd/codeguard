"""Follow-ups to the 2026-10-08 tour fixes.

  1. A credential dismissal's stated reason is the value's SHAPE and
     nothing else. Live, on codeguard-playground, the model dismissed by
     shape but still added "the file header explicitly states these are
     fake placeholders" -- the outcome was right and the reason was not.
     The reason is now written from the shape the guard itself checked,
     per occurrence, so it cannot cite a comment.
  2. "How to fix" is per line, like "What": a `lines` entry may be an
     object carrying its own fix. The plain-string form still parses.
  3. With the structured fields present, `message` is one sentence (the
     contract says so; the cost of saying everything twice was +32%).
  4. A taint finding says where the tainted string was BUILT as well as
     where it reached the model: "assigned at line 44, sent to the model
     at line 49".
  5. The PR review path merges the same bug from two rules into one
     finding (one inline comment listing both rule ids) and skips B101 in
     test files, exactly as audits do.
"""

from __future__ import annotations

import json
import re
from unittest.mock import patch

from codeguard.config import RepoConfig
from codeguard.diff.filters import split_test_asserts
from codeguard.pipeline import nodes
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.merge import flow_note, rule_label
from codeguard.pipeline.nodes import review_ai_aware, summarize
from codeguard.redact import secret_values
from codeguard.severity import Severity
from codeguard.tools.models import Finding
from codeguard.tools.semgrep_runner import _parse
from codeguard.worker.main import _findings_to_review_comments, _tool_findings_for_review
from tests.pipeline.conftest import make_finding

_COMMENT_WORDS = re.compile(r"(?i)comment|docstring|header|says|states|claims|documented|noted|readme")


def _result(items) -> AgentCallResult:
    return AgentCallResult(raw_text=json.dumps(items), tokens_in=10, tokens_out=5,
                           estimated_cost_usd=0.001, latency_s=0.01)


def _state(content, findings):
    return {"owner": "o", "repo": "r", "path": "assistant.py", "content": content,
            "patch": "", "findings": findings, "hunk_cache_hits": {}}


# --------------------------------------------------------------------------
# 1. The dismissal reason cites only the shape
# --------------------------------------------------------------------------

PLAYGROUND_SHAPED = (
    '"""DEMO CODE. The credentials below are obviously fake placeholders, not real keys."""\n'
    'import openai\n'
    'client = openai.OpenAI(api_key="sk-placeholder-not-a-real-key-000000000000")\n'
    'ANTHROPIC_API_KEY = "placeholder-not-a-real-key-2222222222222222"\n'
)


def test_a_credential_dismissal_reason_cites_only_the_shape():
    findings = [
        make_finding(file="assistant.py", line=3, tool="semgrep", rule_id="rules.llm-hardcoded-api-key"),
        make_finding(file="assistant.py", line=4, tool="semgrep", rule_id="rules.llm-hardcoded-api-key"),
    ]
    verdict = [{"rule_id": "rules.llm-hardcoded-api-key", "verdict": "dismissed",
                "message": "Placeholder-like, and the file header explicitly states these are fake."}]
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(verdict)):
        out = review_ai_aware(_state(PLAYGROUND_SHAPED, findings))

    reasons = {d.start_line: d.reason for d in out["dismissed_findings"]}
    assert set(reasons) == {3, 4}
    for reason in reasons.values():
        assert "placeholder-like" in reason
        assert not _COMMENT_WORDS.search(reason), reason
    # Each occurrence's own shape, not one paragraph about all of them.
    assert "42-char sk-style token" in reasons[3]
    assert "43-char token" in reasons[4]


def test_secret_values_reports_each_value_once():
    assert len(secret_values('client = OpenAI(api_key="sk-placeholder-not-a-real-key-000000000000")')) == 1


# --------------------------------------------------------------------------
# 2 and 3. Per-line fixes; a one-sentence message
# --------------------------------------------------------------------------

def _sql(line):
    return make_finding(file="db.py", line=line, tool="bandit", rule_id="B608")


def test_a_lines_entry_may_carry_its_own_fix():
    items = [{
        "rule_id": "B608", "verdict": "confirmed", "severity": "high",
        "message": "SQL is built from parameters.",
        "lines": {
            "13": {"what": "email is %-formatted into the query.", "fix": "Bind email as a parameter."},
            "29": {"what": "table is .format()ed into the query.", "fix": "Check table against an allowlist."},
        },
        "fix": "Use parameterized queries.",
    }]
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(items)):
        out = nodes.review_security({"owner": "o", "repo": "r", "path": "db.py",
                                     "content": "x\n" * 40, "patch": "", "findings": [_sql(13), _sql(29)],
                                     "hunk_cache_hits": {}})

    by_line = {f.start_line: f for f in out["findings"]}
    assert by_line[13].fix == "Bind email as a parameter."
    assert by_line[29].fix == "Check table against an allowlist."
    assert "allowlist" not in by_line[13].message and "email" not in by_line[29].message


def test_the_contract_asks_for_per_line_fixes_and_a_one_sentence_message():
    c = nodes._VERDICT_CONTRACT
    assert '"fix"' in c and "per line" in c.lower()
    assert "ONE sentence" in c
    assert "cite only the shape" in c.lower()


# --------------------------------------------------------------------------
# 4. Where the tainted string was built
# --------------------------------------------------------------------------

def _semgrep_json(source_line, sink_line):
    return json.dumps({"results": [{
        "check_id": "rules.llm-prompt-injection-concatenation", "path": "/tmp/x/assistant.py",
        "start": {"line": sink_line}, "end": {"line": sink_line},
        "extra": {"severity": "ERROR", "message": "Untrusted input concatenated into a prompt.",
                  "dataflow_trace": {"taint_source": ["CliLoc", [
                      {"start": {"line": source_line, "col": 14}, "end": {"line": source_line, "col": 60},
                       "path": "/tmp/x/assistant.py"}, "..."]]}},
    }]})


def test_the_semgrep_runner_records_where_the_taint_came_from():
    [f] = _parse(_semgrep_json(44, 49), "/tmp/x")
    assert (f.start_line, f.source_line) == (49, 44)
    assert f.message == "Untrusted input concatenated into a prompt."  # fingerprint input unchanged


def test_a_source_on_the_sink_line_is_not_a_separate_location():
    [f] = _parse(_semgrep_json(49, 49), "/tmp/x")
    assert f.source_line == 0


def test_the_flow_note_names_both_lines():
    f = make_finding(file="assistant.py", line=49).model_copy(update={"source_line": 44})
    assert flow_note(f) == "Assigned at line 44, sent to the model at line 49."


def test_a_verdict_keeps_the_source_line_and_says_so():
    raw = make_finding(file="assistant.py", line=49, tool="semgrep",
                       rule_id="rules.llm-prompt-injection-concatenation").model_copy(update={"source_line": 44})
    items = [{"rule_id": "rules.llm-prompt-injection-concatenation", "verdict": "confirmed",
              "severity": "high", "message": "User input is spliced into the prompt."}]
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(items)):
        out = review_ai_aware(_state("x\n" * 60, [raw]))

    [f] = out["findings"]
    assert f.source_line == 44
    assert "Assigned at line 44, sent to the model at line 49." in f.message


# --------------------------------------------------------------------------
# 5. The PR review path: merge and B101
# --------------------------------------------------------------------------

def _pr_state(findings, **over):
    state = {
        "owner": "o", "repo": "r", "pr_number": 1, "head_sha": "sha", "installation_id": 1,
        "repo_config": RepoConfig(), "files": {"assistant.py": ""},
        "patches": {"assistant.py": "@@ -60,0 +60,10 @@\n" + "+x\n" * 10},
        "tool_findings": [], "touches_ai_code": False,
        "findings": findings, "repo_level_findings": [], "dismissed_findings": [],
        "fix_suggestions": [], "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
        "suppressed_fingerprints": frozenset(), "budget_exceeded": False,
    }
    state.update(over)
    return state


def _summarize(state):
    intro = AgentCallResult(raw_text="Intro.", tokens_in=1, tokens_out=1, estimated_cost_usd=0.0, latency_s=0.0)
    with patch("codeguard.pipeline.nodes.call_agent", return_value=intro):
        return summarize(state)


def test_the_same_bug_from_two_rules_is_one_inline_comment_on_a_pr():
    findings = [
        Finding.create(file="assistant.py", start_line=64, end_line=64, severity=Severity.HIGH,
                       source_tool="security", rule_id="B307", message="eval() of model output."),
        Finding.create(file="assistant.py", start_line=64, end_line=64, severity=Severity.CRITICAL,
                       source_tool="ai_aware", rule_id="rules.llm-output-to-dangerous-sink",
                       message="Model output flows into eval()."),
    ]
    out = _summarize(_pr_state(findings))

    inline = out["inline_findings"]
    assert len(inline) == 1
    assert set(inline[0].sources) == {"B307", "llm-output-to-dangerous-sink"}
    [comment] = _findings_to_review_comments(inline, [])
    assert "B307" in comment["body"] and "llm-output-to-dangerous-sink" in comment["body"]


def test_rule_label_lists_every_source():
    f = make_finding(rule_id="rules.llm-output-to-dangerous-sink").model_copy(
        update={"sources": ["llm-output-to-dangerous-sink", "B307"]})
    assert rule_label(f) == "llm-output-to-dangerous-sink, B307"
    assert rule_label(make_finding(rule_id="B105")) == "B105"


def test_the_worker_skips_test_asserts_before_the_graph():
    tool_findings = [
        make_finding(file="tests/test_x.py", tool="bandit", rule_id="B101"),
        make_finding(file="app/core.py", tool="bandit", rule_id="B101"),
    ]
    kept, skipped = _tool_findings_for_review(1, tool_findings)
    assert skipped == 1
    assert [f.file for f in kept] == ["app/core.py"]
    assert split_test_asserts(tool_findings)[1] == 1


def test_the_pr_summary_says_how_many_test_asserts_were_skipped():
    out = _summarize(_pr_state([], skipped_test_asserts=83))
    assert "83 test asserts" in out["summary"]


def test_no_skipped_line_when_none_were_skipped():
    out = _summarize(_pr_state([]))
    assert "test assert" not in out["summary"]
