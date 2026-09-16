"""Regression coverage for summarize()'s own logic, tested directly
(not through the whole graph) since none of this depends on fan-out —
dedup by fingerprint, outside-diff findings routed to the summary body
instead of inline, the inline-comment cap, and the always-post-a-body
guarantee even with zero findings. No GitHub calls: summarize() is a
plain function over state, posting happens in the worker afterward.

summarize() also calls call_agent once (the Haiku summary
intro) — mocked here (see _mock_summary_call) so this stays a
zero-network-call test file; tests/pipeline/test_summary_intro.py
covers that call's own behavior (success, failure, what it's given).
"""

from __future__ import annotations

from unittest.mock import patch

from codeguard.config import RepoConfig, get_settings
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.models import DismissedFinding, FixSuggestion
from codeguard.pipeline.nodes import summarize
from codeguard.severity import Severity
from tests.pipeline.conftest import make_finding


def _mock_summary_call(*, agent, **kwargs):
    assert agent == "summary"
    return AgentCallResult(raw_text="Mock intro.", tokens_in=1, tokens_out=1, estimated_cost_usd=0.0, latency_s=0.0)


def _state(findings, patches, files=None, repo_config=None, dismissed_findings=None, suppressed_fingerprints=None):
    return {
        "owner": "o", "repo": "r", "pr_number": 1, "head_sha": "sha", "installation_id": 1,
        "repo_config": repo_config or RepoConfig(),
        "files": files or {p: "" for p in patches},
        "patches": patches,
        "tool_findings": [],
        "touches_ai_code": False,
        "findings": findings, "repo_level_findings": [], "dismissed_findings": dismissed_findings or [],
        "fix_suggestions": [],
        "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
        "suppressed_fingerprints": suppressed_fingerprints or frozenset(),
    }


def _summarize(state):
    with patch("codeguard.pipeline.nodes.call_agent", side_effect=_mock_summary_call):
        return summarize(state)


def test_summarize_dedupes_by_fingerprint():
    f1 = make_finding(file="a.py", line=5, rule_id="B105", message="same issue")
    f2 = make_finding(file="a.py", line=5, rule_id="B105", message="same issue")
    assert f1.fingerprint == f2.fingerprint  # sanity: these really are duplicates

    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}
    result = _summarize(_state([f1, f2], patches))

    assert len(result["inline_findings"]) == 1
    assert "found 1 issue" in result["summary"]


def test_finding_outside_diff_goes_to_summary_body_not_inline():
    # patch only covers lines 1-5; finding at line 50 is nowhere near it.
    f = make_finding(file="a.py", line=50, rule_id="B105", message="out of range")
    patches = {"a.py": "@@ -1,5 +1,5 @@\n context"}

    result = _summarize(_state([f], patches))

    assert result["inline_findings"] == []  # never dropped...
    assert "a.py:50" in result["summary"]   # ...just not inline
    assert "B105" in result["summary"]


def test_finding_inside_diff_is_inlined():
    f = make_finding(file="a.py", line=3, rule_id="B105", message="in range")
    patches = {"a.py": "@@ -1,5 +1,5 @@\n context"}

    result = _summarize(_state([f], patches))

    assert len(result["inline_findings"]) == 1
    assert result["inline_findings"][0].fingerprint == f.fingerprint


def test_inline_comment_cap_keeps_top_n_by_severity_rest_in_body():
    cap = get_settings().max_inline_comments  # same source of truth summarize() itself uses

    findings = []
    patches = {}
    for i in range(cap + 5):
        sev = Severity.HIGH if i < 5 else Severity.LOW
        f = make_finding(file=f"f{i}.py", line=1, rule_id=f"R{i}", message=f"issue {i}", severity=sev)
        findings.append(f)
        patches[f"f{i}.py"] = "@@ -1,3 +1,3 @@\n context"

    result = _summarize(_state(findings, patches))

    assert len(result["inline_findings"]) == cap
    inlined_ids = {f.rule_id for f in result["inline_findings"]}
    for i in range(5):
        assert f"R{i}" in inlined_ids, "a HIGH-severity finding was bumped by a LOW one"
    assert "additional finding" in result["summary"]


def test_zero_findings_still_produces_a_body():
    result = _summarize(_state([], {}, files={"a.py": "", "b.py": ""}))

    assert result["inline_findings"] == []
    assert "no issues found" in result["summary"]
    assert "2 file(s)" in result["summary"]


def test_dismissed_findings_appear_in_body_alongside_confirmed_ones():
    f = make_finding(file="a.py", line=3, rule_id="B105", message="confirmed one")
    d = DismissedFinding(file="a.py", start_line=9, rule_id="llm-unpinned-model-alias", reason="pinned by internal proxy")
    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}

    result = _summarize(_state([f], patches, dismissed_findings=[d]))

    assert "checked by an AI agent, not flagged" in result["summary"]
    assert "a.py:9" in result["summary"]
    assert "llm-unpinned-model-alias" in result["summary"]
    assert "pinned by internal proxy" in result["summary"]
    # the dismissal never displaces the confirmed finding from inline
    assert len(result["inline_findings"]) == 1


def test_dismissed_findings_appear_even_with_zero_confirmed_findings():
    d = DismissedFinding(file="a.py", start_line=9, rule_id="llm-unpinned-model-alias", reason="pinned by internal proxy")

    result = _summarize(_state([], {}, files={"a.py": ""}, dismissed_findings=[d]))

    assert "no issues found" in result["summary"]
    assert "checked by an AI agent, not flagged" in result["summary"]
    assert result["inline_findings"] == []


def test_low_confidence_finding_goes_to_summary_body_not_inline():
    """A Quality/Test finding below quality_test_min_inline_confidence
    is demoted to the summary body even though it's on a real diff line —
    the same demotion an out-of-diff finding already gets, never dropped."""
    threshold = get_settings().quality_test_min_inline_confidence
    f = make_finding(file="a.py", line=3, rule_id="quality.naming", tool="quality-agent",
                      message="low confidence", confidence=threshold - 0.01)
    patches = {"a.py": "@@ -1,5 +1,5 @@\n context"}

    result = _summarize(_state([f], patches))

    assert result["inline_findings"] == []
    assert "quality.naming" in result["summary"]


def test_high_confidence_finding_is_still_inlined():
    threshold = get_settings().quality_test_min_inline_confidence
    f = make_finding(file="a.py", line=3, rule_id="quality.naming", tool="quality-agent",
                      message="confident", confidence=threshold)
    patches = {"a.py": "@@ -1,5 +1,5 @@\n context"}

    result = _summarize(_state([f], patches))

    assert len(result["inline_findings"]) == 1


def test_suppressed_fingerprint_never_appears_inline_or_in_summary():
    """A fingerprint a maintainer already marked false_positive
    on a past PR is excluded before dedup — not demoted like a
    low-confidence or out-of-diff finding, fully absent."""
    f = make_finding(file="a.py", line=3, rule_id="B105", message="suppressed one")
    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}

    result = _summarize(_state([f], patches, suppressed_fingerprints=frozenset({f.fingerprint})))

    assert result["inline_findings"] == []
    assert "B105" not in result["summary"]
    assert "no issues found" in result["summary"]


def test_unsuppressed_fingerprint_alongside_a_suppressed_one_still_shows():
    suppressed = make_finding(file="a.py", line=3, rule_id="B105", message="suppressed one")
    real = make_finding(file="a.py", line=5, rule_id="B608", message="real issue")
    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}

    result = _summarize(_state([suppressed, real], patches, suppressed_fingerprints=frozenset({suppressed.fingerprint})))

    assert len(result["inline_findings"]) == 1
    assert result["inline_findings"][0].rule_id == "B608"


def test_no_dismissed_section_when_there_are_no_dismissals():
    f = make_finding(file="a.py", line=3, rule_id="B105", message="confirmed one")
    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}

    result = _summarize(_state([f], patches, dismissed_findings=[]))

    assert "checked by an AI agent" not in result["summary"]


def test_summary_intro_prepended_when_call_succeeds():
    f = make_finding(file="a.py", line=3, rule_id="B105", message="confirmed one")
    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}

    result = _summarize(_state([f], patches))

    assert result["summary"].startswith("Mock intro.")
    assert result["tokens_in"] == 1 and result["tokens_out"] == 1


def test_summary_intro_omitted_when_call_fails():
    f = make_finding(file="a.py", line=3, rule_id="B105", message="confirmed one")
    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}

    def _failing(*, agent, **kwargs):
        return AgentCallResult(raw_text=None, error="boom")

    with patch("codeguard.pipeline.nodes.call_agent", side_effect=_failing):
        result = summarize(_state([f], patches))

    assert result["summary"].startswith("CodeGuard reviewed")
    assert "tokens_in" not in result


# --- Grouped dismissals in a <details> block, consistent
# found/dismissed counts, quality.docs as a count-only footnote, and
# exact fix-threshold wording — all found via CodeGuard's own live
# review of one of its own PRs (see evals/RESULTS.md).

def test_dismissed_findings_with_same_rule_and_reason_are_grouped_into_one_entry():
    f = make_finding(file="a.py", line=3, rule_id="B105", message="confirmed one")
    reason = "Assert statements are standard in test code."
    d1 = DismissedFinding(file="b.py", start_line=10, rule_id="B101", reason=reason)
    d2 = DismissedFinding(file="b.py", start_line=20, rule_id="B101", reason=reason)
    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}

    result = _summarize(_state([f], patches, dismissed_findings=[d1, d2]))

    assert "<details>" in result["summary"] and "</details>" in result["summary"]
    assert "1 finding(s) checked by an AI agent" in result["summary"]  # ONE grouped entry, not two
    assert "b.py (lines 10, 20)" in result["summary"]


def test_dismissed_findings_with_different_reasons_are_not_grouped_together():
    d1 = DismissedFinding(file="b.py", start_line=10, rule_id="B101", reason="reason one")
    d2 = DismissedFinding(file="b.py", start_line=20, rule_id="B101", reason="reason two")

    result = _summarize(_state([], {}, files={"b.py": ""}, dismissed_findings=[d1, d2]))

    assert "2 finding(s) checked by an AI agent" in result["summary"]
    assert "reason one" in result["summary"] and "reason two" in result["summary"]


def test_dismissed_count_never_exceeds_found_count_after_grouping():
    """The exact shape found live on PR #3: one Bandit rule dismissed
    identically across many lines of one file used to report a
    dismissed count bigger than the (already-deduped) found count."""
    f = make_finding(file="a.py", line=1, rule_id="B608", message="real issue")
    reason = "Assert statements are standard in test code."
    many_dismissals = [DismissedFinding(file="b.py", start_line=i, rule_id="B101", reason=reason) for i in range(1, 30)]
    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}

    result = _summarize(_state([f], patches, dismissed_findings=many_dismissals))

    assert "1 finding(s) checked by an AI agent" in result["summary"]  # 29 raw dismissals -> 1 group
    assert "found 1 issue" in result["summary"]


def test_confirmed_findings_on_different_lines_with_same_message_are_grouped_in_the_body():
    f1 = make_finding(file="a.py", line=50, rule_id="B105", tool="bandit", message="same rationale")
    f2 = make_finding(file="a.py", line=80, rule_id="B105", tool="bandit", message="same rationale")
    patches = {"a.py": "@@ -1,5 +1,5 @@\n context"}  # neither line is in the diff -> both go to the body

    result = _summarize(_state([f1, f2], patches))

    assert "1 additional finding(s) not shown inline" in result["summary"]  # grouped count, matches what's printed
    assert result["summary"].count("same rationale") == 1  # one line, not two identical ones
    assert "a.py (lines 50, 80)" in result["summary"]


def test_quality_docs_findings_are_never_inlined_and_shown_as_a_count_only():
    doc_finding = make_finding(file="a.py", line=3, rule_id="quality.docs", tool="quality-agent", message="missing docstring")
    patches = {"a.py": "@@ -1,5 +1,5 @@\n context"}

    result = _summarize(_state([doc_finding], patches))

    assert result["inline_findings"] == []
    assert "missing docstring" not in result["summary"]  # never itemized
    assert "1 documentation (quality.docs) finding(s) not shown individually" in result["summary"]
    assert "found 1 issue" in result["summary"]  # still counted in the total


def test_quality_docs_alongside_a_real_finding_only_the_real_one_is_itemized():
    doc_finding = make_finding(file="a.py", line=3, rule_id="quality.docs", tool="quality-agent", message="missing docstring")
    real_finding = make_finding(file="b.py", line=1, rule_id="B608", tool="bandit", message="sqli")
    patches = {"a.py": "@@ -1,5 +1,5 @@\n context", "b.py": "@@ -1,5 +1,5 @@\n context"}

    result = _summarize(_state([doc_finding, real_finding], patches))

    assert len(result["inline_findings"]) == 1
    assert result["inline_findings"][0].rule_id == "B608"
    assert "1 documentation (quality.docs) finding(s) not shown individually" in result["summary"]


def test_no_fix_suggestions_reports_the_fix_threshold_by_name():
    f = make_finding(file="a.py", line=3, rule_id="B105", message="x")
    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}

    result = _summarize(_state([f], patches, repo_config=RepoConfig(fix_threshold=Severity.HIGH)))

    assert "No findings met the fix threshold (HIGH)." in result["summary"]
    assert "no fix suggestions were generated" not in result["summary"].lower()


def test_fix_suggestions_present_reports_the_count_not_the_threshold_line():
    f = make_finding(file="a.py", line=3, rule_id="B105", message="x")
    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}
    suggestion = FixSuggestion(fingerprint=f.fingerprint, suggestion_body="fixed_code()")

    with patch("codeguard.pipeline.nodes.call_agent", side_effect=_mock_summary_call):
        state = _state([f], patches)
        state["fix_suggestions"] = [suggestion]
        result = summarize(state)

    assert "1 fix suggestion(s) proposed." in result["summary"]
    assert "No findings met the fix threshold" not in result["summary"]
