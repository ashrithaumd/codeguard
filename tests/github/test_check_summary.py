"""Covers the Check Run summary body. Pure rendering — no network, no
DB, and deliberately no LLM, which is itself part of the contract here:
the panel a reviewer reads to decide whether to trust the review must be
identical for identical inputs.
"""

from __future__ import annotations

from codeguard.github.check_summary import (
    MAX_FIELD_CHARS,
    escape_finding_text,
    render_check_summary,
    unavailable_tools,
)
from codeguard.severity import Severity
from codeguard.tools.base import UNAVAILABLE_RULE_ID
from codeguard.tools.models import Finding


def make(file="app/db.py", line=42, severity=Severity.HIGH, tool="security", rule_id="B608",
         message="possible SQL injection"):
    return Finding.create(
        file=file, start_line=line, end_line=line, severity=severity,
        source_tool=tool, rule_id=rule_id, message=message, confidence=1.0,
    )


def unavailable(tool="semgrep"):
    return Finding.create(
        file="<pr>", start_line=0, end_line=0, severity=Severity.LOW,
        source_tool=tool, rule_id=UNAVAILABLE_RULE_ID,
        message=f"{tool} unavailable: Expecting value: line 1 column 1 (char 0)",
    )


def render(**overrides):
    kwargs = dict(
        findings=[], tool_findings=[], blocking=[], gate_threshold=Severity.HIGH,
        files_seen=4, files_reviewed=4, budget_exceeded=False,
        fix_suggestion_count=0, dismissed_count=0,
        tokens_in=1000, tokens_out=100, estimated_cost_usd=0.0123, duration_s=9.87,
    )
    kwargs.update(overrides)
    return render_check_summary(**kwargs)


# --- severity table ---------------------------------------------------


def test_severity_table_counts_every_level_including_the_empty_ones():
    """A fixed four-row table, not one row per level that happens to be
    present: "High 0" is information, and a table whose shape changes
    with the data is harder to read at a glance.
    """
    findings = [
        make(severity=Severity.CRITICAL),
        make(severity=Severity.MEDIUM, line=7),
        make(severity=Severity.MEDIUM, line=9),
    ]

    body = render(findings=findings)

    assert "| Critical | 1 |" in body
    assert "| High | 0 |" in body
    assert "| Medium | 2 |" in body
    assert "| Low | 0 |" in body


def test_total_finding_count_and_files_reviewed_lead_the_body():
    body = render(findings=[make(), make(line=9)], files_seen=11, files_reviewed=6)

    assert "**2 finding(s)** across 6 of 11 changed file(s) reviewed." in body


# --- trust buckets ----------------------------------------------------


def test_verification_table_splits_confirmed_generative_and_unverified():
    """The buckets come from pipeline/reviews.py's classify_findings, so
    this asserts the summary reports the same classification the reviews
    row stores rather than a second, drifting one.
    """
    findings = [
        make(tool="security"),                       # verdict-confirmed
        make(tool="ai_aware", line=3),               # verdict-confirmed
        make(tool="quality-agent", line=5),          # generative
        make(tool="ruff", line=7),                   # deterministic
        make(tool="bandit", line=9),                 # unverified
    ]

    body = render(findings=findings)

    assert "| Confirmed by an LLM verdict | 2 |" in body
    assert "| Proposed by an LLM (capped MEDIUM) | 1 |" in body
    assert "| Deterministic tool, no verdict layer | 1 |" in body
    assert "| Unverified | 1 |" in body


# --- scope, economics, gate -------------------------------------------


def test_fix_suggestions_cost_and_duration_are_reported():
    body = render(
        findings=[make()], fix_suggestion_count=3, dismissed_count=17,
        tokens_in=48213, tokens_out=3907, estimated_cost_usd=0.0412, duration_s=48.31,
    )

    assert "Fix suggestions proposed: **3**" in body
    assert "Checked by an agent and dismissed: **17**" in body
    assert "Cost: **$0.0412** (48,213 in / 3,907 out tokens)" in body
    assert "Duration: **48.3s**" in body


def test_gate_line_names_the_worst_blocking_finding():
    low = make(severity=Severity.HIGH, rule_id="R1")
    worst = make(severity=Severity.CRITICAL, rule_id="R2", file="app/x.py", line=9)

    body = render(findings=[low, worst], blocking=[low, worst], gate_threshold=Severity.HIGH)

    assert "Gate: **2** finding(s) at or above **HIGH**." in body
    assert "`R2`" in body
    assert "`app/x.py:9`" in body


def test_gate_line_says_so_when_nothing_blocks():
    body = render(findings=[make(severity=Severity.LOW)], blocking=[], gate_threshold=Severity.HIGH)

    assert "Gate: no finding at or above **HIGH**." in body


# --- zero findings ----------------------------------------------------


def test_zero_findings_gets_a_sentence_not_an_empty_table():
    body = render(findings=[], files_seen=3, files_reviewed=3)

    assert "**No findings.** 3 of 3 changed file(s) reviewed." in body
    assert "| Severity | Count |" not in body
    assert "| Verification | Count |" not in body
    assert "Cost: **$0.0123**" in body   # economics still reported


# --- warnings ---------------------------------------------------------


def test_truncation_warning_states_how_much_was_not_reviewed():
    body = render(findings=[make()], budget_exceeded=True, files_seen=40, files_reviewed=15)

    assert "> [!WARNING]" in body
    assert "only 15 of 40 changed file(s) were reviewed" in body
    assert "max_files_per_pr" in body


def test_no_truncation_warning_when_the_whole_diff_was_reviewed():
    assert "[!WARNING]" not in render(findings=[make()])


def test_truncation_warning_survives_the_zero_finding_branch():
    """The dangerous combination: nothing found, most of the diff never
    looked at. The short clean summary must not swallow the warning.
    """
    body = render(findings=[], budget_exceeded=True, files_seen=40, files_reviewed=15)

    assert "**No findings.**" in body
    assert "> [!WARNING]" in body
    assert body.index("[!WARNING]") < body.index("**No findings.**")


def test_a_tool_that_did_not_run_is_called_out_by_name():
    body = render(findings=[make()], tool_findings=[unavailable("semgrep")])

    assert "> [!CAUTION]" in body
    assert "`semgrep` did not run" in body


def test_tool_warning_is_absent_when_every_tool_ran():
    body = render(findings=[make()], tool_findings=[make(tool="bandit", rule_id="B105")])

    assert "[!CAUTION]" not in body


def test_both_warnings_appear_together_and_lead_the_body():
    body = render(
        findings=[make()], tool_findings=[unavailable("semgrep")],
        budget_exceeded=True, files_seen=40, files_reviewed=15,
    )

    assert body.index("[!WARNING]") < body.index("[!CAUTION]") < body.index("**1 finding(s)**")


def test_unavailable_tools_reads_the_raw_tool_findings_deduped_and_sorted():
    """The meta-finding is file="<pr>", which every pipeline node filters
    away by path — worker/main.py's raw tool_findings is the only place
    it still exists by the time the Check Run is completed.
    """
    findings = [unavailable("semgrep"), unavailable("bandit"), unavailable("semgrep"), make()]

    assert unavailable_tools(findings) == ["bandit", "semgrep"]


# --- escaping ---------------------------------------------------------


def test_finding_text_is_html_escaped():
    assert escape_finding_text("<img src=x onerror=alert(1)>") == "&lt;img src=x onerror=alert(1)&gt;"


def test_pipes_are_neutralised_so_a_finding_cannot_break_a_table_row():
    assert "|" not in escape_finding_text("a|b.py")
    assert "&#124;" in escape_finding_text("a|b.py")


def test_newlines_are_flattened():
    assert escape_finding_text("line one\nline two") == "line one line two"


def test_overlong_field_is_truncated():
    escaped = escape_finding_text("x" * (MAX_FIELD_CHARS * 3))

    assert len(escaped) == MAX_FIELD_CHARS + 1   # + the ellipsis
    assert escaped.endswith("…")


def test_a_hostile_finding_reaches_the_rendered_body_escaped():
    """End-to-end on the only path a finding's own text is interpolated:
    the gate line. Bandit's hardcoded-secret message echoes the matched
    source verbatim, so this text is PR-author-influenceable.
    """
    hostile = make(file="a|b.py", rule_id="<script>alert(1)</script>", severity=Severity.CRITICAL)

    body = render(findings=[hostile], blocking=[hostile])

    assert "<script>" not in body
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in body
    assert "a&#124;b.py:42" in body


# --- determinism ------------------------------------------------------


def test_rendering_is_deterministic_for_identical_input():
    """No LLM call, no timestamp, no set iteration leaking into the
    output — the same review must always produce the same panel.
    """
    findings = [make(tool="security"), make(tool="quality-agent", line=3), make(tool="ruff", line=5)]
    kwargs = dict(findings=findings, blocking=findings[:1], tool_findings=[unavailable("semgrep")],
                  budget_exceeded=True, files_seen=40, files_reviewed=15)

    assert render(**kwargs) == render(**kwargs)
