"""Regression coverage for the two defects that corrupted the first live
review on codeguard-playground PR #5 (head e89e9c6).

The reviewed file is 22 lines. Its whole content is one hunk — the patch
is `@@ -0,0 +1,22 @@`, so build_hunks produces exactly one Hunk spanning
lines 1-22 (reconstructed from the real patch and file content, not
assumed). Relevant lines:

      2      query = "SELECT * FROM users WHERE email = '%s'" % email
     13          return a * b          <- multiplication
     14      elif op == "div":
     15          return a / b          <- the actual division

What was posted:

  - `[security / HIGH] B608` on line 2, carrying "Also flagged by 1 other
    agent(s)" — i.e. folded — and NO fix suggestion, though every prior
    run attached a parameterized-query one there.
  - `[quality-agent / MEDIUM] quality.error-handling` on **line 2**, whose
    message read "The division operation on line 13 lacks protection
    against division by zero", carrying a suggestion replacing that line
    with `if b == 0: raise ValueError(...) / return a / b`. Committing it
    would have replaced the SQL statement with division code.

Two independent causes:

  1. _apply_fold rebuilt the survivor with Finding.create(), which
     derives the fingerprint from the message. Folding rewrites the
     message, so the survivor got a NEW identity and the suggestion
     propose_fix had keyed to the pre-fold fingerprint matched nothing.
     (propose_fix runs before summarize — see graph.py.)

  2. The quality agent itself returned line 2 for a finding whose message
     described a division. It is worth being precise about what this is
     NOT: the hunk was 1-22, so _parse_direct_findings' old line clamp
     (min(max(line, hunk_start), hunk_end)) was a no-op here and cannot
     have produced 2 — and note the model's own message is wrong twice,
     since the division is on line 15, not 13. Every line number in the
     pipeline was then self-consistent: the finding said 2, the
     suggestion was generated for 2, it was posted on 2. No comparison of
     line numbers against each other can detect that. The only
     disagreement was between the suggestion's CONTENT and the code
     actually at that line, which is what _echoes_the_findings_own_lines
     now checks.
"""

from __future__ import annotations

import json
from unittest.mock import patch as mock_patch

from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.models import FixSuggestion
from codeguard.pipeline.nodes import (
    _apply_fold,
    _echoes_the_findings_own_lines,
    _fold_cross_agent_duplicates,
    _parse_direct_findings,
    propose_fix,
)
from codeguard.severity import Severity
from codeguard.tools.models import Finding
from codeguard.worker.main import _findings_to_review_comments

PATH = "validation_test.py"
SQL_LINE = 2
MULTIPLY_LINE = 13
DIVISION_LINE = 15

FILE_CONTENT = '''def get_user_by_email(cursor, email):
    query = "SELECT * FROM users WHERE email = '%s'" % email
    cursor.execute(query)
    return cursor.fetchone()


def calc(a, b, op):
    if op == "add":
        return a + b
    elif op == "sub":
        return a - b
    elif op == "mul":
        return a * b
    elif op == "div":
        return a / b
'''

PATCH = "@@ -0,0 +1,22 @@"

SQL_ORIGINAL = '''    query = "SELECT * FROM users WHERE email = '%s'" % email'''
SQL_REPLACEMENT = '''    query = "SELECT * FROM users WHERE email = %s"'''
DIVISION_REPLACEMENT = '''        if b == 0:
            raise ValueError("Division by zero")
        return a / b'''


def finding(*, line, severity, tool, rule_id, message):
    return Finding.create(
        file=PATH, start_line=line, end_line=line, severity=severity,
        source_tool=tool, rule_id=rule_id, message=message, confidence=1.0,
    )


def fix_state(findings):
    return {
        "owner": "o", "repo": "r", "path": PATH, "content": FILE_CONTENT,
        "patch": PATCH, "findings": findings,
    }


def run_propose_fix(findings, items):
    result = AgentCallResult(
        raw_text=json.dumps(items), tokens_in=1, tokens_out=1,
        estimated_cost_usd=0.0, latency_s=0.0,
    )
    with mock_patch("codeguard.pipeline.nodes.call_agent", return_value=result):
        return propose_fix(fix_state(findings))


# --- cause 2: the suggestion is about different code than the line ------


def test_the_live_case_a_division_fix_generated_for_the_sql_line_is_dropped():
    """The exact production input: a quality finding placed on line 2 by
    the model itself, whose message describes a division, and a fix agent
    that wrote division code for it.
    """
    mislocated = finding(
        line=SQL_LINE, severity=Severity.MEDIUM, tool="quality-agent",
        rule_id="quality.error-handling",
        message="The division operation on line 13 lacks protection against division by zero.",
    )

    out = run_propose_fix([mislocated], [{
        "fingerprint": mislocated.fingerprint,
        # The fix agent echoes the division lines, because that is what it
        # actually wrote a replacement for — while the finding sits on
        # line 2.
        "original": "        return a / b",
        "replacement": DIVISION_REPLACEMENT,
    }])

    assert out["fix_suggestions"] == [], "a suggestion replacing the SQL line with division code must not survive"


def test_a_suggestion_that_really_does_replace_its_findings_line_survives():
    sql = finding(
        line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
        message="SQL injection vulnerability confirmed.",
    )

    out = run_propose_fix([sql], [{
        "fingerprint": sql.fingerprint,
        "original": SQL_ORIGINAL,
        "replacement": SQL_REPLACEMENT,
    }])

    [suggestion] = out["fix_suggestions"]
    assert SQL_REPLACEMENT in suggestion.suggestion_body
    assert suggestion.target_line == SQL_LINE


def test_a_missing_original_fails_closed():
    """Losing a suggestion costs a click; applying a wrong one corrupts
    the file, so an unverifiable suggestion is dropped.
    """
    sql = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
                  message="SQL injection")

    out = run_propose_fix([sql], [{"fingerprint": sql.fingerprint, "replacement": SQL_REPLACEMENT}])

    assert out["fix_suggestions"] == []


def test_echo_check_compares_against_the_findings_own_lines():
    file_lines = FILE_CONTENT.splitlines()
    sql = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608", message="m")

    assert _echoes_the_findings_own_lines(SQL_ORIGINAL, file_lines, sql)
    assert _echoes_the_findings_own_lines(SQL_ORIGINAL + "   ", file_lines, sql), "trailing space is noise"
    assert not _echoes_the_findings_own_lines("        return a / b", file_lines, sql)
    assert not _echoes_the_findings_own_lines(SQL_ORIGINAL.lstrip(), file_lines, sql), "indentation matters"
    assert not _echoes_the_findings_own_lines("", file_lines, sql)


def test_echo_check_rejects_a_line_outside_the_file():
    file_lines = FILE_CONTENT.splitlines()
    beyond = finding(line=9999, severity=Severity.LOW, tool="quality-agent", rule_id="q.x", message="m")

    assert not _echoes_the_findings_own_lines("anything", file_lines, beyond)


# --- cause 1: the fold destroying finding identity ----------------------


def test_folded_finding_keeps_its_fix_suggestion_and_each_lands_on_its_own_line():
    """Two findings in one file, one folded, a suggestion generated for
    each, asserted to land on its own finding's line.
    """
    sql = finding(
        line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
        message="SQL injection vulnerability confirmed. The query uses string formatting.",
    )
    # Same line, message contains "sql" -> folded in by the B608 anchor.
    # This is what actually happened on PR #5.
    test_dup = finding(
        line=SQL_LINE, severity=Severity.MEDIUM, tool="test-agent", rule_id="test.test",
        message="SQL injection vulnerability in get_user_by_email is not tested.",
    )
    division = finding(
        line=DIVISION_LINE, severity=Severity.MEDIUM, tool="quality-agent",
        rule_id="quality.error-handling",
        message="The division operation lacks protection against division by zero.",
    )

    suggestions = [
        FixSuggestion(fingerprint=sql.fingerprint,
                      suggestion_body=f"```suggestion\n{SQL_REPLACEMENT}\n```",
                      target_file=PATH, target_line=SQL_LINE),
        FixSuggestion(fingerprint=division.fingerprint,
                      suggestion_body=f"```suggestion\n{DIVISION_REPLACEMENT}\n```",
                      target_file=PATH, target_line=DIVISION_LINE),
    ]

    folded = _fold_cross_agent_duplicates([sql, test_dup, division])
    comments = _findings_to_review_comments(folded, suggestions)

    by_line = {c["line"]: c["body"] for c in comments}
    assert set(by_line) == {SQL_LINE, DIVISION_LINE}

    assert "Also flagged by 1 other agent(s)" in by_line[SQL_LINE]
    assert SQL_REPLACEMENT in by_line[SQL_LINE]
    assert "return a / b" not in by_line[SQL_LINE], "the PR #5 corruption"
    assert "raise ValueError" not in by_line[SQL_LINE]

    assert DIVISION_REPLACEMENT in by_line[DIVISION_LINE]
    assert "cursor.execute" not in by_line[DIVISION_LINE]


def test_fold_preserves_the_primarys_fingerprint():
    """A fold changes how a finding renders, never which finding it is."""
    primary = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
                      message="SQL injection confirmed")
    other = finding(line=SQL_LINE, severity=Severity.MEDIUM, tool="quality-agent",
                    rule_id="quality.error-handling", message="sql injection here too")

    result = _apply_fold(primary, [other])

    assert result.fingerprint == primary.fingerprint
    assert result.start_line == primary.start_line
    assert "Also flagged by 1 other agent(s)" in result.message


# --- post-time identity guard -------------------------------------------


def test_a_suggestion_whose_target_moved_is_dropped_not_posted():
    f = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
                message="SQL injection")
    stale = FixSuggestion(
        fingerprint=f.fingerprint, suggestion_body=f"```suggestion\n{DIVISION_REPLACEMENT}\n```",
        target_file=PATH, target_line=DIVISION_LINE,
    )

    [comment] = _findings_to_review_comments([f], [stale])

    assert comment["line"] == SQL_LINE
    assert "```suggestion" not in comment["body"]
    assert "SQL injection" in comment["body"], "the finding itself is still reported"


def test_a_suggestion_recorded_before_the_target_fields_existed_is_kept():
    f = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
                message="SQL injection")
    legacy = FixSuggestion(fingerprint=f.fingerprint, suggestion_body=f"```suggestion\n{SQL_REPLACEMENT}\n```")

    [comment] = _findings_to_review_comments([f], [legacy])

    assert SQL_REPLACEMENT in comment["body"]


# --- the line clamp (hardening; NOT the cause of the PR #5 bug) ---------


def test_a_reported_line_outside_the_hunk_is_demoted_not_relocated():
    """Separate latent defect found while investigating, kept because
    clamping is wrong regardless. It did NOT cause the PR #5 corruption:
    that hunk was 1-22 and the reported line was 2, so the clamp never
    engaged.
    """
    items = [{"line": 999, "severity": "MEDIUM", "category": "error-handling", "message": "out of range"}]

    [result] = _parse_direct_findings(
        items, path=PATH, agent="quality",
        hunk_start=1, hunk_end=SQL_LINE, max_severity=Severity.MEDIUM, max_findings=10,
    )

    assert result.start_line == 0, "0 means 'no specific line', routed to the summary body"
    assert "out of range" in result.message, "the finding is kept, only its coordinates are dropped"


def test_the_real_pr5_hunk_leaves_every_relevant_line_untouched():
    """Pins the fact that makes the clamp irrelevant to PR #5."""
    items = [{"line": n, "severity": "MEDIUM", "category": "c", "message": f"about line {n}"}
             for n in (SQL_LINE, MULTIPLY_LINE, DIVISION_LINE)]

    results = _parse_direct_findings(
        items, path=PATH, agent="quality",
        hunk_start=1, hunk_end=22, max_severity=Severity.MEDIUM, max_findings=10,
    )

    assert [f.start_line for f in results] == [SQL_LINE, MULTIPLY_LINE, DIVISION_LINE]
