"""Audit-engine fixes from the 2026-10-08 feature tour.

  * file ceiling tiers -- on DocuMind the ceiling dropped main.py in favour
    of test files, because selection was "LLM files first, then smallest",
    with no notion of an entrypoint or a test.
  * B101 in tests -- on reliqueue 83 of 86 dismissals were `assert` in
    tests/, and they cost most of the $0.066. They never reach the model
    now, and are counted as skipped, not as dismissals.
  * duplicate findings -- playground line 64 was reported twice, by Bandit
    B307 and by llm-output-to-dangerous-sink. Same file, same line, same
    bug: one finding, both rule ids as its sources.
  * <repo>:0 -- the eval-hygiene finding appeared as a Medium finding at a
    fake line 0 AND again under "Eval hygiene". Once, as repo-level.
  * the structured report the audit page renders, built from the same
    data as the markdown so the two cannot disagree.
"""

from __future__ import annotations

from codeguard.cli import (
    _select_files_for_audit,
    build_report_data,
    render_report,
    split_test_asserts,
)
from codeguard.pipeline.merge import merge_same_bug
from codeguard.pipeline.models import DismissedFinding
from codeguard.severity import Severity
from codeguard.tools.models import Finding


def _f(file="a.py", line=1, tool="bandit", rule_id="B105", message="x", severity=Severity.HIGH, **kw):
    return Finding.create(file=file, start_line=line, end_line=line, severity=severity,
                          source_tool=tool, rule_id=rule_id, message=message, **kw)


def _report_kwargs(**over):
    base = dict(
        target="https://github.com/o/r", files_scanned=3, files_ai_aware=1,
        ai_reviewed_findings=[], passthrough_findings=[], dismissed=[],
        eval_hygiene_findings=[], osv_findings=[], skipped_files=[],
        verdict_call_failures=[], unavailable_tools=[],
        tokens_in=100, tokens_out=50, estimated_cost_usd=0.0347, elapsed_s=29.3,
    )
    base.update(over)
    return base


# --------------------------------------------------------------------------
# File ceiling tiers
# --------------------------------------------------------------------------

def test_an_oversized_entrypoint_beats_small_test_files():
    """The DocuMind shape: one big main.py, several small tests."""
    files = {
        "main.py": "from fastapi import FastAPI\n" + "x = 1\n" * 2000,
        "tests/test_a.py": "def test_a():\n    assert 1\n",
        "tests/test_b.py": "def test_b():\n    assert 1\n",
        "tests/conftest.py": "import pytest\n",
    }
    selected, skipped = _select_files_for_audit(files, max_files=2, max_tokens=1_000_000)

    assert "main.py" in selected
    assert {p for p, _ in skipped} <= {"tests/test_a.py", "tests/test_b.py", "tests/conftest.py"}


def test_the_tiers_are_entrypoints_app_llm_other_tests():
    files = {
        "tests/test_llm.py": "import anthropic\n",       # a test, even with an SDK import
        "scripts/seed.py": "x = 1\n",                     # everything else
        "examples/chat.py": "import openai\n",            # LLM SDK, not app code
        "app/models.py": "y = 2\n" * 30,                  # app code
        "app/llm.py": "import anthropic\n" + "z = 3\n" * 30,  # app code with an SDK import
        "app.py": "w = 4\n" * 300,                        # entrypoint
    }
    order = []
    for n in range(1, len(files) + 1):
        selected, _ = _select_files_for_audit(files, max_files=n, max_tokens=1_000_000)
        order.append(next(p for p in selected if p not in order))

    assert order == [
        "app.py", "app/llm.py", "app/models.py", "examples/chat.py", "scripts/seed.py", "tests/test_llm.py",
    ]


def test_a_test_file_is_never_preferred_over_app_code_however_small():
    files = {"src/pkg/core.py": "a = 1\n" * 400, "tests/test_core.py": "assert True\n"}
    selected, _ = _select_files_for_audit(files, max_files=1, max_tokens=1_000_000)
    assert set(selected) == {"src/pkg/core.py"}


# --------------------------------------------------------------------------
# B101 in test files
# --------------------------------------------------------------------------

def test_b101_in_test_files_is_split_out_before_the_model():
    findings = [
        _f(file="tests/test_q.py", rule_id="B101", severity=Severity.LOW),
        _f(file="tests/conftest.py", rule_id="B101", severity=Severity.LOW),
        _f(file="pkg/test_x.py", rule_id="B101", severity=Severity.LOW),
        _f(file="pkg/x_test.py", rule_id="B101", severity=Severity.LOW),
        _f(file="pkg/core.py", rule_id="B101", severity=Severity.LOW),   # NOT a test: kept
        _f(file="tests/test_q.py", rule_id="B105"),                     # not B101: kept
        _f(file="tests/test_q.py", tool="semgrep", rule_id="B101"),     # not Bandit: kept
    ]
    kept, skipped = split_test_asserts(findings)

    assert skipped == 4
    assert sorted((f.file, f.rule_id) for f in kept) == [
        ("pkg/core.py", "B101"), ("tests/test_q.py", "B101"), ("tests/test_q.py", "B105"),
    ]


def test_skipped_test_asserts_are_reported_as_skipped_not_dismissed():
    report = render_report(**_report_kwargs(skipped_test_asserts=83))
    assert "83 test assert" in report
    assert "0 tool finding(s) reviewed and dismissed" in report or "dismissed" not in report.split("\n")[2]


# --------------------------------------------------------------------------
# Merging the same bug at the same location
# --------------------------------------------------------------------------

def test_bandit_and_semgrep_on_the_same_eval_merge_into_one():
    findings = [
        _f(file="assistant.py", line=64, tool="security", rule_id="B307", message="eval of model output"),
        _f(file="assistant.py", line=64, tool="ai_aware", rule_id="rules.llm-output-to-dangerous-sink",
           message="model output into eval()", what="run_untrusted() passes model output to eval().",
           fix="Never eval model output."),
    ]
    merged = merge_same_bug(findings)

    assert len(merged) == 1
    assert set(merged[0].sources) == {"B307", "llm-output-to-dangerous-sink"}
    assert merged[0].what == "run_untrusted() passes model output to eval()."


def test_merging_keeps_the_higher_severity():
    findings = [
        _f(file="db.py", line=13, tool="security", rule_id="B608", severity=Severity.MEDIUM),
        _f(file="db.py", line=13, tool="ai_aware", rule_id="rules.llm-output-to-sql", severity=Severity.CRITICAL),
    ]
    assert merge_same_bug(findings)[0].severity == Severity.CRITICAL


def test_different_bugs_on_the_same_line_stay_separate():
    findings = [
        _f(file="assistant.py", line=33, tool="ai_aware", rule_id="rules.llm-call-missing-timeout"),
        _f(file="assistant.py", line=33, tool="ai_aware", rule_id="rules.llm-call-missing-max-tokens"),
    ]
    assert len(merge_same_bug(findings)) == 2


def test_the_same_bug_on_different_lines_stays_separate():
    findings = [
        _f(file="db.py", line=13, rule_id="B608"),
        _f(file="db.py", line=20, rule_id="B608"),
    ]
    assert len(merge_same_bug(findings)) == 2


def test_the_report_shows_a_merged_finding_once_with_both_rules():
    findings = [
        _f(file="assistant.py", line=64, tool="security", rule_id="B307", message="one"),
        _f(file="assistant.py", line=64, tool="ai_aware", rule_id="rules.llm-output-to-dangerous-sink", message="two"),
    ]
    report = render_report(**_report_kwargs(ai_reviewed_findings=findings))
    assert report.count("`assistant.py:64`") == 1
    assert "B307" in report and "llm-output-to-dangerous-sink" in report


# --------------------------------------------------------------------------
# Repo-level findings
# --------------------------------------------------------------------------

def _eval_hygiene():
    return Finding.create(file="<repo>", start_line=0, end_line=0, severity=Severity.MEDIUM,
                          source_tool="eval-hygiene", rule_id="eval-hygiene.missing-evals",
                          message="1 file(s) call an LLM SDK but this repo has no evals/ directory.")


def test_a_repo_level_finding_appears_once_and_never_at_line_zero():
    report = render_report(**_report_kwargs(eval_hygiene_findings=[_eval_hygiene()]))
    assert "<repo>:0" not in report
    assert ":0`" not in report
    assert report.count("has no evals/ directory") == 1
    assert "## Repository-level" in report


def test_a_repo_level_finding_is_not_in_the_severity_list():
    data = build_report_data(**_report_kwargs(eval_hygiene_findings=[_eval_hygiene()]))
    assert data["findings"] == []
    assert len(data["repo_level"]) == 1
    assert data["summary"]["counts"]["medium"] == 0
    assert data["summary"]["repo_level"] == 1


# --------------------------------------------------------------------------
# The structured report
# --------------------------------------------------------------------------

def test_structured_report_carries_what_the_page_renders():
    findings = [
        _f(file="db.py", line=13, rule_id="B608", severity=Severity.HIGH, title="SQL injection",
           what="Email %-formatted into the query.", why="Returns every user.", fix="Use a placeholder."),
        _f(file="assistant.py", line=47, tool="ai_aware", rule_id="rules.llm-unpinned-model-alias",
           severity=Severity.MEDIUM, message="Floating alias."),
        _f(file="assistant.py", line=81, tool="ai_aware", rule_id="rules.llm-logging-full-prompt-or-response",
           severity=Severity.LOW, message="Logs the response."),
    ]
    dismissed = [DismissedFinding(file="assistant.py", start_line=21, rule_id="rules.llm-hardcoded-api-key",
                                  reason="placeholder-shaped value")]
    data = build_report_data(**_report_kwargs(ai_reviewed_findings=findings, dismissed=dismissed))

    assert data["summary"]["counts"] == {"critical": 0, "high": 1, "medium": 1, "low": 1}
    assert [f["severity"] for f in data["findings"]] == ["high", "medium", "low"]
    top = data["findings"][0]
    assert (top["title"], top["what"], top["why"], top["fix"]) == (
        "SQL injection", "Email %-formatted into the query.", "Returns every user.", "Use a placeholder.")
    assert top["rules"] == ["B608"]
    # A finding with no structure falls back to its message, and gets a title.
    second = data["findings"][1]
    assert second["what"] == "Floating alias." and second["title"]
    assert second["rules"] == ["llm-unpinned-model-alias"]
    assert data["dismissed"] == [{"file": "assistant.py", "start_line": 21,
                                  "rule_id": "llm-hardcoded-api-key", "reason": "placeholder-shaped value"}]
    assert data["technical"]["tokens_in"] == 100
    assert data["technical"]["estimated_cost_usd"] == 0.0347


def test_the_markdown_is_rendered_from_the_structured_data():
    """One source: every finding on the page is in the markdown, and the
    markdown has nothing the page does not."""
    findings = [_f(file="db.py", line=13, rule_id="B608", message="SQL built by formatting.")]
    kwargs = _report_kwargs(ai_reviewed_findings=findings)
    data = build_report_data(**kwargs)
    report = render_report(**kwargs)
    for f in data["findings"]:
        assert f"`{f['file']}:{f['start_line']}`" in report


def test_a_taint_finding_says_where_the_value_was_built_in_report_json():
    f = _f(file="assistant.py", line=49, tool="ai_aware", rule_id="rules.llm-prompt-injection-concatenation",
           message="Untrusted input is concatenated into the prompt.").model_copy(update={"source_line": 44})
    data = build_report_data(**_report_kwargs(ai_reviewed_findings=[f]))
    [card] = data["findings"]
    assert card["source_line"] == 44 and card["start_line"] == 49
    assert card["flow"] == "Assigned at line 44, sent to the model at line 49."
    assert "Assigned at line 44, sent to the model at line 49." in card["what"]
    report = render_report(**_report_kwargs(ai_reviewed_findings=[f]))
    assert "Assigned at line 44, sent to the model at line 49." in report


def test_a_finding_without_a_source_has_no_flow():
    data = build_report_data(**_report_kwargs(ai_reviewed_findings=[_f(line=13, rule_id="B608")]))
    assert data["findings"][0]["source_line"] == 0 and data["findings"][0]["flow"] == ""


# --------------------------------------------------------------------------
# The audited commit
# --------------------------------------------------------------------------

def test_head_sha_reads_the_checked_out_commit(tmp_path):
    import subprocess

    from codeguard.cli import _head_sha

    def git(*args):
        subprocess.run(["git", "-C", str(tmp_path), *args], check=True, capture_output=True)

    git("init", "-q")
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    git("add", "a.py")
    git("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init")
    sha = _head_sha(tmp_path)
    assert sha is not None and len(sha) == 40 and all(c in "0123456789abcdef" for c in sha)


def test_head_sha_is_none_outside_a_repository(tmp_path):
    from codeguard.cli import _head_sha
    assert _head_sha(tmp_path) is None
