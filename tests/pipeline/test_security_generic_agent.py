"""The security_generic verdict agent: findings from the vendored rules in
JS/TS, Go, Java and C#.

Same verdict contract as the Python agents (the scanner found it; the agent
only confirms or dismisses). Its own prompt, its own cache key. Content goes
out redacted with PLAIN masks -- no shape hints -- and with every span the
secrets scan matched already masked, so nothing about a secret reaches the
model. Routed only for files the triage chose; never for Python files.

Mocked model throughout. No live calls.
"""

from __future__ import annotations

import random
import string
from unittest.mock import patch

from codeguard.config import RepoConfig
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.nodes import (
    _SECURITY_GENERIC_SYSTEM_PROMPT,
    review_security_generic,
    route_to_generic_security_reviews,
    verdict_cache_agent,
)
from codeguard.severity import Severity
from codeguard.tools.models import Finding

JS = "function run(userInput) {\n  return eval(userInput);\n}\n"


def _f(file="web/run.js", line=2, rule="javascript_eval_rule-eval-with-expression"):
    return Finding.create(file=file, start_line=line, end_line=line, severity=Severity.HIGH,
                          source_tool="gitlab-sast", rule_id=rule, message="eval with a non-literal argument")


def _model(text):
    return AgentCallResult(raw_text=text, tokens_in=500, tokens_out=60, estimated_cost_usd=0.004, latency_s=0.2)


def _file_state(content=JS, findings=None):
    return {"owner": "o", "repo": "r", "path": "web/run.js", "content": content, "patch": "",
            "findings": findings or [_f()], "hunk_cache_hits": {}}


def test_the_prompt_is_its_own_and_carries_the_verdict_contract():
    assert "Semgrep" in _SECURITY_GENERIC_SYSTEM_PROMPT and "Bandit" not in _SECURITY_GENERIC_SYSTEM_PROMPT
    assert '"verdict"' in _SECURITY_GENERIC_SYSTEM_PROMPT and "dismissed" in _SECURITY_GENERIC_SYSTEM_PROMPT
    assert verdict_cache_agent("security_generic") == "security_generic/v2"


def test_a_confirmed_verdict_comes_back_as_a_finding():
    reply = ('[{"rule_id": "javascript_eval_rule-eval-with-expression", "verdict": "confirmed", '
             '"severity": "high", "message": "User input reaches eval."}]')
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_model(reply)) as call:
        out = review_security_generic(_file_state())
    assert call.call_args.kwargs["agent"] == "security_generic"
    assert call.call_args.kwargs["system_prompt"] == _SECURITY_GENERIC_SYSTEM_PROMPT
    [f] = out["findings"]
    assert (f.file, f.start_line, f.severity) == ("web/run.js", 2, Severity.HIGH)
    assert out["cache_writes"][0].agent == "security_generic/v2"


def test_a_dismissal_is_recorded_with_its_reason():
    reply = ('[{"rule_id": "javascript_eval_rule-eval-with-expression", "verdict": "dismissed", '
             '"message": "The argument is a constant from a fixed allowlist."}]')
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_model(reply)):
        out = review_security_generic(_file_state())
    assert out["findings"] == [] and [d.rule_id for d in out["dismissed_findings"]] == [
        "javascript_eval_rule-eval-with-expression"]


def test_content_goes_out_with_plain_masks_not_shape_hints():
    rng = random.Random(3)
    key = "sk-" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(40))
    content = f'const apiKey = "{key}";\n' + JS
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_model("[]")) as call:
        review_security_generic(_file_state(content=content, findings=[_f(line=3)]))
    sent = call.call_args.kwargs["user_content"]
    assert key not in sent
    assert "[redacted]" in sent and "[redacted:" not in sent  # a mask, not a description of the value


def test_a_failed_call_falls_back_to_unreviewed_findings():
    failed = AgentCallResult(raw_text=None, error="timeout", latency_s=30.0)
    with patch("codeguard.pipeline.nodes.call_agent", return_value=failed):
        out = review_security_generic(_file_state())
    assert all(f.unreviewed for f in out["findings"]) and out["verdict_call_failures"][0].agent == "security_generic"


def _review_state(**over):
    state = {"owner": "o", "repo": "r", "pr_number": 1, "head_sha": "s", "repo_config": RepoConfig(),
             "files": {"app.py": "x = 1\n"}, "patches": {}, "tool_findings": [], "hunk_cache_hits": {}}
    state.update(over)
    return state


def test_routing_sends_one_review_per_chosen_file_and_none_for_python():
    state = _review_state(generic_files={"web/run.js": JS, "cmd/a.go": "package a\n"},
                          generic_findings={"web/run.js": [_f()], "cmd/a.go": [_f("cmd/a.go", 1, "go_sql_rule")]})
    sends = route_to_generic_security_reviews(state)
    assert sorted(s.arg["path"] for s in sends) == ["cmd/a.go", "web/run.js"]
    assert {s.node for s in sends} == {"review_security_generic"}


def test_a_python_only_review_routes_nothing():
    assert route_to_generic_security_reviews(_review_state()) == []


# --------------------------------------------------------------------------
# End to end through the real graph
# --------------------------------------------------------------------------

def _graph_state(**over):
    state = {
        "owner": "o", "repo": "r", "pr_number": 1, "head_sha": "sha", "installation_id": 1,
        "repo_config": RepoConfig(), "files": {}, "patches": {"web/run.js": "@@ -0,0 +1,3 @@\n+a\n+b\n+c"},
        "tool_findings": [], "base_tree_files": {}, "budget_exceeded": False, "hunk_cache_hits": {},
        "cache_writes": [], "suppressed_fingerprints": frozenset(), "touches_ai_code": False,
        "findings": [], "repo_level_findings": [], "dismissed_findings": [], "fix_suggestions": [],
        "should_fix": False, "summary": "", "inline_findings": [], "tokens_in": 0, "tokens_out": 0,
        "estimated_cost_usd": 0.0, "node_latencies": [],
    }
    state.update(over)
    return state


async def test_the_graph_runs_the_generic_agent_and_its_verdict_reaches_the_results():
    from codeguard.pipeline.graph import review_graph

    agents = []

    def fake(*, agent, **kwargs):
        agents.append(agent)
        if agent == "security_generic":
            return _model('[{"rule_id": "javascript_eval_rule-eval-with-expression", "verdict": "confirmed", '
                          '"severity": "high", "message": "User input reaches eval."}]')
        return _model("Intro.")

    with patch("codeguard.pipeline.nodes.call_agent", side_effect=fake):
        out = await review_graph.ainvoke(_graph_state(
            generic_files={"web/run.js": JS}, generic_findings={"web/run.js": [_f()]}, generic_scanned=["web/run.js"]))
    assert agents.count("security_generic") == 1
    # Labelled by the agent that judged it, as the Python agents do ("security").
    assert [(f.file, f.source_tool) for f in out["findings"]] == [("web/run.js", "security_generic")]
    assert "reviewed 1 file(s)" in out["summary"]


async def test_a_python_only_review_never_calls_the_generic_agent():
    from codeguard.pipeline.graph import review_graph

    agents = []

    def fake(*, agent, **kwargs):
        agents.append(agent)
        return _model("Intro.")

    with patch("codeguard.pipeline.nodes.call_agent", side_effect=fake):
        await review_graph.ainvoke(_graph_state(files={"app.py": "x = 1\n"}, patches={"app.py": "@@ -0,0 +1 @@\n+x = 1"}))
    assert "security_generic" not in agents


def test_our_own_rules_keep_their_severity_and_vendored_ones_take_the_models():
    # codeguard-js-llm-call-missing-timeout came back Medium in four files and
    # Low in seven of the same audit (openai-quickstart-node): one call per
    # file, and the model picked the severity each time. For CodeGuard's own
    # rules the rule's severity stands; the model only confirms or dismisses.
    # Vendored GitLab findings keep the model's severity, as before.
    own = Finding.create(file="web/run.js", start_line=1, end_line=1, severity=Severity.MEDIUM,
                         source_tool="codeguard-rules", rule_id="codeguard-js-llm-call-missing-timeout",
                         message="client has no timeout")
    reply = ('[{"rule_id": "codeguard-js-llm-call-missing-timeout", "verdict": "confirmed", "severity": "low", '
             '"message": "No timeout."}, '
             '{"rule_id": "javascript_eval_rule-eval-with-expression", "verdict": "confirmed", "severity": "low", '
             '"message": "eval of input."}]')
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_model(reply)):
        out = review_security_generic(_file_state(findings=[own, _f()]))
    by_rule = {f.rule_id: f.severity for f in out["findings"]}
    assert by_rule == {"codeguard-js-llm-call-missing-timeout": Severity.MEDIUM,
                       "javascript_eval_rule-eval-with-expression": Severity.LOW}
