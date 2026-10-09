"""A failed verdict call must not look like a normal run.

When the model call behind a verdict fails -- a timeout, an outage, an
exhausted credit balance -- the raw scanner findings are reported instead.
That fallback is right (a finding is never dropped because the model was
unreachable) and it stays. What was wrong is that the result looked
exactly like a reviewed one: found live on 2026-10-08, when the account's
credit ran out mid-eval and every call after that "succeeded" into the
raw fallback without a visible trace.

Now each fallback finding is marked `unreviewed`, and the audit report,
the audit page, the review detail page and the PR summary all say
"AI review unavailable for N finding(s); shown unreviewed."

Every test here uses a mocked failing client. No live calls.
"""

from __future__ import annotations

from unittest.mock import patch

from codeguard.cli import _run_verdict_layer, build_report_data, render_report
from codeguard.config import RepoConfig
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.nodes import review_ai_aware, review_security, summarize
from codeguard.worker.main import _findings_to_review_comments
from tests.pipeline.conftest import make_finding

NOTICE = "AI review unavailable for {n} finding(s); shown unreviewed."
CREDIT = ("Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', "
          "'message': 'Your credit balance is too low to access the Anthropic API.'}}")


def _failed(error=CREDIT) -> AgentCallResult:
    return AgentCallResult(raw_text=None, error=error)


def _state(findings, content="x\n" * 80):
    return {"owner": "o", "repo": "r", "path": "app.py", "content": content,
            "patch": "", "findings": findings, "hunk_cache_hits": {}}


def test_a_failed_security_call_marks_its_findings_unreviewed():
    raw = [make_finding(file="app.py", line=13, tool="bandit", rule_id="B608"),
           make_finding(file="app.py", line=20, tool="bandit", rule_id="B608")]
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_failed()):
        out = review_security(_state(raw))

    assert len(out["findings"]) == 2, "the fallback stays: nothing is dropped"
    assert all(f.unreviewed for f in out["findings"])
    assert len(out["verdict_call_failures"]) == 1


def test_a_failed_ai_aware_call_marks_its_findings_unreviewed():
    raw = [make_finding(file="app.py", line=49, tool="semgrep", rule_id="rules.llm-call-missing-timeout")]
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_failed("APITimeoutError")):
        out = review_ai_aware(_state(raw))
    assert [f.unreviewed for f in out["findings"]] == [True]


def test_a_successful_call_marks_nothing_unreviewed():
    raw = [make_finding(file="app.py", line=13, tool="bandit", rule_id="B608")]
    ok = AgentCallResult(raw_text='[{"rule_id": "B608", "verdict": "confirmed", "severity": "high", '
                                  '"message": "SQL built by formatting."}]', tokens_in=1, tokens_out=1)
    with patch("codeguard.pipeline.nodes.call_agent", return_value=ok):
        out = review_security(_state(raw))
    assert [f.unreviewed for f in out["findings"]] == [False]


# --------------------------------------------------------------------------
# Audits
# --------------------------------------------------------------------------

def test_the_audit_verdict_layer_counts_failed_calls_and_marks_findings():
    files = {"db.py": "x\n" * 30}
    raw = {"db.py": [make_finding(file="db.py", line=13, tool="bandit", rule_id="B608")]}
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_failed()):
        result = _run_verdict_layer(review_security, "audit", "r", files, raw)

    assert len(result.call_failures) == 1
    assert [f.unreviewed for f in result.confirmed] == [True]


def _report_kwargs(findings, failures):
    return dict(
        target="https://github.com/o/r", files_scanned=1, files_ai_aware=0,
        ai_reviewed_findings=findings, passthrough_findings=[], dismissed=[],
        eval_hygiene_findings=[], osv_findings=[], skipped_files=[],
        verdict_call_failures=failures, unavailable_tools=[],
        tokens_in=0, tokens_out=0, estimated_cost_usd=0.0, elapsed_s=1.0,
    )


def test_the_audit_report_says_so_and_marks_each_finding():
    findings = [make_finding(file="db.py", line=13, tool="bandit", rule_id="B608").model_copy(update={"unreviewed": True}),
                make_finding(file="db.py", line=20, tool="bandit", rule_id="B608").model_copy(update={"unreviewed": True}),
                make_finding(file="a.py", line=3, tool="ruff", rule_id="F401")]
    kwargs = _report_kwargs(findings, [("db.py", "lines 1-30: security call failed (credit)")])
    data = build_report_data(**kwargs)

    assert data["summary"]["unreviewed"] == 2
    assert data["summary"]["verdict_calls_failed"] == 1
    assert [f["unreviewed"] for f in data["findings"] if f["file"] == "db.py"] == [True, True]
    assert NOTICE.format(n=2) in render_report(**kwargs)


def test_no_notice_when_every_call_succeeded():
    kwargs = _report_kwargs([make_finding(file="a.py", line=3, tool="ruff", rule_id="F401")], [])
    assert "AI review unavailable" not in render_report(**kwargs)
    assert build_report_data(**kwargs)["summary"]["unreviewed"] == 0


# --------------------------------------------------------------------------
# PR reviews
# --------------------------------------------------------------------------

def _pr_state(findings):
    return {
        "owner": "o", "repo": "r", "pr_number": 1, "head_sha": "sha", "installation_id": 1,
        "repo_config": RepoConfig(), "files": {"db.py": ""},
        "patches": {"db.py": "@@ -10,0 +10,20 @@\n" + "+x\n" * 20},
        "tool_findings": [], "touches_ai_code": False,
        "findings": findings, "repo_level_findings": [], "dismissed_findings": [],
        "fix_suggestions": [], "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
        "suppressed_fingerprints": frozenset(), "budget_exceeded": False,
    }


def test_the_pr_summary_and_inline_comment_say_so():
    f = make_finding(file="db.py", line=13, tool="bandit", rule_id="B608").model_copy(update={"unreviewed": True})
    intro = AgentCallResult(raw_text="Intro.", tokens_in=1, tokens_out=1)
    with patch("codeguard.pipeline.nodes.call_agent", return_value=intro):
        out = summarize(_pr_state([f]))

    assert NOTICE.format(n=1) in out["summary"]
    [comment] = _findings_to_review_comments(out["inline_findings"], [])
    assert "Unreviewed" in comment["body"]


def test_a_reviewed_pr_has_no_notice():
    f = make_finding(file="db.py", line=13, tool="security", rule_id="B608")
    intro = AgentCallResult(raw_text="Intro.", tokens_in=1, tokens_out=1)
    with patch("codeguard.pipeline.nodes.call_agent", return_value=intro):
        out = summarize(_pr_state([f]))
    assert "AI review unavailable" not in out["summary"]
    [comment] = _findings_to_review_comments(out["inline_findings"], [])
    assert "Unreviewed" not in comment["body"]
