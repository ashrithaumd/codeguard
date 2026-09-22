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
     actually at that line, which is what _matched_replacement_range
     now checks.
"""

from __future__ import annotations

import json
from unittest.mock import patch as mock_patch

from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.models import FixSuggestion
from codeguard.pipeline.nodes import (
    _apply_fold,
    _breaks_a_file_that_parsed,
    _fold_cross_agent_duplicates,
    _is_model_located,
    _matched_replacement_range,
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

    Now stopped twice over: _is_model_located drops it before the echo
    check is ever consulted, and _breaks_a_file_that_parsed would have
    caught the same replacement independently (8-space-indented division
    code spliced in as the first statement of a 4-space body does not
    parse). The echo check's own coverage of this shape lives in
    test_a_grounded_findings_mismatched_echo_is_still_dropped, which uses
    a grounded finding so the earlier drop doesn't mask it.
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

    assert _matched_replacement_range(SQL_ORIGINAL, file_lines, sql)
    assert _matched_replacement_range(SQL_ORIGINAL + "   ", file_lines, sql), "trailing space is noise"
    assert not _matched_replacement_range("        return a / b", file_lines, sql)
    assert not _matched_replacement_range(SQL_ORIGINAL.lstrip(), file_lines, sql), "indentation matters"
    assert not _matched_replacement_range("", file_lines, sql)


def test_echo_check_rejects_a_line_outside_the_file():
    file_lines = FILE_CONTENT.splitlines()
    beyond = finding(line=9999, severity=Severity.LOW, tool="quality-agent", rule_id="q.x", message="m")

    assert not _matched_replacement_range("anything", file_lines, beyond)


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


# --- the gap: a correct echo with an unrelated replacement --------------


def test_a_correct_echo_does_not_make_an_unrelated_replacement_safe():
    """The variant the echo check does NOT cover by construction.

    Here the fix agent echoes line 2's SQL text correctly — so `original`
    genuinely matches the finding's own line — but the replacement it
    returns is division code. The suggestion would still replace the SQL
    statement with `if b == 0: ... return a / b`.

    _matched_replacement_range answers "are you replacing the line
    you say you are?". It cannot answer "is what you are putting there
    related to that line at all?", because it never looks at
    `replacement`.

    Was xfail(strict=True) while the fix was undecided. Closed by
    _is_model_located: this finding is a quality-agent one, so no
    suggestion is generated for it at all. Kept as a regression — it is
    the exact shape the gap had, and it is worth failing loudly if a
    generative finding ever reaches propose_fix again. Note the echo
    check itself is NOT what makes it pass now; see
    test_a_grounded_findings_mismatched_echo_is_still_dropped for that
    path's own coverage.
    """
    mislocated = finding(
        line=SQL_LINE, severity=Severity.MEDIUM, tool="quality-agent",
        rule_id="quality.error-handling",
        message="The division operation on line 13 lacks protection against division by zero.",
    )

    out = run_propose_fix([mislocated], [{
        "fingerprint": mislocated.fingerprint,
        "original": SQL_ORIGINAL,              # correct echo of line 2
        "replacement": DIVISION_REPLACEMENT,   # but unrelated code
    }])

    assert out["fix_suggestions"] == []


# --- C: a model-located finding never gets a suggestion -----------------


def test_a_grounded_findings_mismatched_echo_is_still_dropped():
    """The echo check's own coverage at the propose_fix level, on a
    grounded finding so _is_model_located doesn't drop it first.

    Without this, every propose_fix-level test of the echo check would
    pass for the wrong reason once C landed, and the check could rot
    unnoticed.
    """
    sql = finding(
        line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
        message="SQL injection vulnerability confirmed.",
    )

    out = run_propose_fix([sql], [{
        "fingerprint": sql.fingerprint,
        "original": "        return a / b",   # not what line 2 says
        "replacement": SQL_REPLACEMENT,
    }])

    assert out["fix_suggestions"] == []


def test_is_model_located_splits_generative_from_grounded():
    """Pins the discriminator itself, so a new generative agent added
    later can't quietly inherit suggestion-generating rights.
    """
    for tool in ("quality-agent", "test-agent"):
        assert _is_model_located(finding(line=1, severity=Severity.LOW, tool=tool, rule_id="r", message="m"))
    for tool in ("security", "ai_aware", "bandit", "semgrep", "ruff", "osv", "eval-hygiene"):
        assert not _is_model_located(finding(line=1, severity=Severity.LOW, tool=tool, rule_id="r", message="m"))


def test_every_finding_parse_direct_findings_builds_is_model_located():
    """The invariant _is_model_located actually depends on: findings
    from the direct-findings contract are marked at construction. Tied
    to the real constructor rather than to a hardcoded list of agent
    names, so a third generative agent is covered the day it is added.
    """
    for agent in ("quality", "test"):
        results = _parse_direct_findings(
            [{"line": 1, "severity": "MEDIUM", "category": "c", "message": "m"}],
            path=PATH, agent=agent, hunk_start=1, hunk_end=22,
            max_severity=Severity.MEDIUM, max_findings=10,
        )
        assert results and all(_is_model_located(f) for f in results)


def test_a_generative_finding_gets_no_suggestion_even_with_a_perfect_echo():
    """The fix agent can return a flawless, genuinely correct suggestion
    for a quality finding and it is still withheld — the objection is to
    the line's provenance, not to the replacement's quality.
    """
    mislocated = finding(
        line=SQL_LINE, severity=Severity.MEDIUM, tool="quality-agent",
        rule_id="quality.error-handling", message="SQL injection here.",
    )

    out = run_propose_fix([mislocated], [{
        "fingerprint": mislocated.fingerprint,
        "original": SQL_ORIGINAL,
        "replacement": SQL_REPLACEMENT,
    }])

    assert out["fix_suggestions"] == []


# --- A: the parse backstop ----------------------------------------------


def test_a_replacement_that_stops_the_file_parsing_is_dropped():
    """A grounded finding with a correct echo — so the echo check passes
    — but a replacement that leaves the file syntactically broken.
    """
    sql = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
                  message="SQL injection")

    out = run_propose_fix([sql], [{
        "fingerprint": sql.fingerprint,
        "original": SQL_ORIGINAL,
        "replacement": '    query = "SELECT * FROM users WHERE email = %s',  # unterminated string
    }])

    assert out["fix_suggestions"] == []


def test_a_file_that_already_does_not_parse_keeps_its_suggestions():
    """The case that makes parse-before matter: PR code is allowed to be
    broken. A file that already fails to parse gives the backstop no
    signal, so it must not become a reason to drop every suggestion for
    that file — which would silently disable fix suggestions on exactly
    the PRs that need review most.
    """
    broken = FILE_CONTENT + "\ndef unclosed(\n"
    sql = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
                  message="SQL injection")

    result = AgentCallResult(
        raw_text=json.dumps([{
            "fingerprint": sql.fingerprint, "original": SQL_ORIGINAL, "replacement": SQL_REPLACEMENT,
        }]),
        tokens_in=1, tokens_out=1, estimated_cost_usd=0.0, latency_s=0.0,
    )
    state = {"owner": "o", "repo": "r", "path": PATH, "content": broken, "patch": PATCH, "findings": [sql]}
    with mock_patch("codeguard.pipeline.nodes.call_agent", return_value=result):
        out = propose_fix(state)

    [suggestion] = out["fix_suggestions"]
    assert SQL_REPLACEMENT in suggestion.suggestion_body


def test_the_parse_backstop_only_fires_on_the_parses_to_broken_transition():
    """The helper directly, over all four before/after combinations."""
    sql = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608", message="m")
    lines = FILE_CONTENT.splitlines()
    broken_lines = (FILE_CONTENT + "\ndef unclosed(\n").splitlines()

    def check(content, file_lines, replacement, path=PATH):
        return _breaks_a_file_that_parsed(
            path=path, content=content, file_lines=file_lines,
            start_line=sql.start_line, end_line=sql.start_line, replacement=replacement,
        )

    good = SQL_REPLACEMENT
    bad = '    query = "unterminated'

    assert not check(FILE_CONTENT, lines, good), "parses -> parses"
    assert check(FILE_CONTENT, lines, bad), "parses -> broken: the only rejection"
    assert not check(FILE_CONTENT + "\ndef unclosed(\n", broken_lines, good), "broken -> broken"
    assert not check(FILE_CONTENT + "\ndef unclosed(\n", broken_lines, bad), "broken before: no signal"


def test_the_parse_backstop_has_no_opinion_on_a_non_python_file():
    """No parser means no opinion — never 'reject'. A .go or .ts file's
    suggestions go through on the echo check alone.
    """
    assert not _breaks_a_file_that_parsed(
        path="main.go", content="package main\n", file_lines=["package main"],
        start_line=1, end_line=1, replacement="func ( {{{",
    )


# --- a fix wider than the finding that prompted it ----------------------

# The real shape of the B608 fix: Bandit flags line 2 (the string being
# built), but parameterizing it also has to change line 3's execute call.
SQL_ORIGINAL_2LINE = SQL_ORIGINAL + "\n    cursor.execute(query)"
SQL_REPLACEMENT_2LINE = (
    '    query = "SELECT * FROM users WHERE email = %s"\n'
    "    cursor.execute(query, (email,))"
)


def test_an_echo_wider_than_the_finding_survives_and_reports_its_own_range():
    """The live regression: every run dropped this suggestion because the
    echo covered lines 2-3 while the B608 finding covers only line 2.
    """
    sql = finding(
        line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
        message="SQL injection vulnerability confirmed.",
    )

    out = run_propose_fix([sql], [{
        "fingerprint": sql.fingerprint,
        "original": SQL_ORIGINAL_2LINE,
        "replacement": SQL_REPLACEMENT_2LINE,
    }])

    [suggestion] = out["fix_suggestions"]
    assert suggestion.target_line == SQL_LINE
    assert suggestion.target_end_line == SQL_LINE + 1, "the range it actually replaces, not the finding's"
    assert "cursor.execute(query, (email,))" in suggestion.suggestion_body


def test_a_wider_echo_is_still_matched_verbatim():
    """Extending past the finding buys the agent no latitude about what
    the code says — the whole range is still compared to the file.
    """
    sql = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608", message="m")
    file_lines = FILE_CONTENT.splitlines()

    assert _matched_replacement_range(SQL_ORIGINAL_2LINE, file_lines, sql) == SQL_LINE + 1
    assert _matched_replacement_range(SQL_ORIGINAL + "\n    cursor.execute(wrong)", file_lines, sql) is None


def test_an_echo_narrower_than_the_finding_is_rejected():
    """Widening is a real need; narrowing gains nothing, so it stays
    rejected rather than being loosened by accident along with it.
    """
    spans_two = Finding.create(
        file=PATH, start_line=SQL_LINE, end_line=SQL_LINE + 1, severity=Severity.HIGH,
        source_tool="security", rule_id="B608", message="m",
    )
    file_lines = FILE_CONTENT.splitlines()

    assert _matched_replacement_range(SQL_ORIGINAL_2LINE, file_lines, spans_two) == SQL_LINE + 1
    assert _matched_replacement_range(SQL_ORIGINAL, file_lines, spans_two) is None


def test_a_range_running_past_the_diff_is_dropped():
    """The whole replaced range has to be in the diff, not just its first
    line — GitHub rejects the comment otherwise, and a range overrunning
    the hunk would rewrite lines the PR never touched.
    """
    sql = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608", message="m")
    result = AgentCallResult(
        raw_text=json.dumps([{
            "fingerprint": sql.fingerprint,
            "original": SQL_ORIGINAL_2LINE,
            "replacement": SQL_REPLACEMENT_2LINE,
        }]),
        tokens_in=1, tokens_out=1, estimated_cost_usd=0.0, latency_s=0.0,
    )
    # Only lines 1-2 are in the diff; the echo reaches line 3.
    state = {
        "owner": "o", "repo": "r", "path": PATH, "content": FILE_CONTENT,
        "patch": "@@ -1,2 +1,2 @@", "findings": [sql],
    }
    with mock_patch("codeguard.pipeline.nodes.call_agent", return_value=result):
        out = propose_fix(state)

    assert out["fix_suggestions"] == []


def test_a_multi_line_suggestion_is_posted_as_a_multi_line_comment():
    """A suggestion block applies to the lines its comment is anchored
    to. Anchored to line 2 alone, this one would insert the replacement
    and leave the original `cursor.execute(query)` behind on line 3.
    """
    sql = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
                  message="SQL injection")
    suggestion = FixSuggestion(
        fingerprint=sql.fingerprint,
        suggestion_body=f"```suggestion\n{SQL_REPLACEMENT_2LINE}\n```",
        target_file=PATH, target_line=SQL_LINE, target_end_line=SQL_LINE + 1,
    )

    [comment] = _findings_to_review_comments([sql], [suggestion])

    assert comment["start_line"] == SQL_LINE
    assert comment["start_side"] == "RIGHT"
    assert comment["line"] == SQL_LINE + 1
    assert "cursor.execute(query, (email,))" in comment["body"]


def test_a_single_line_suggestion_stays_a_single_line_comment():
    """No start_line on the common case — a single-line anchor is what
    GitHub expects, and sending a degenerate range instead would be a
    gratuitous change to every existing comment's shape.
    """
    sql = finding(line=SQL_LINE, severity=Severity.HIGH, tool="security", rule_id="B608",
                  message="SQL injection")
    suggestion = FixSuggestion(
        fingerprint=sql.fingerprint, suggestion_body=f"```suggestion\n{SQL_REPLACEMENT}\n```",
        target_file=PATH, target_line=SQL_LINE, target_end_line=SQL_LINE,
    )

    [comment] = _findings_to_review_comments([sql], [suggestion])

    assert "start_line" not in comment
    assert comment["line"] == SQL_LINE
