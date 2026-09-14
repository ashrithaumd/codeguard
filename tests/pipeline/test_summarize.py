"""Regression coverage for summarize()'s own logic, tested directly
(not through the whole graph) since none of this depends on fan-out —
dedup by fingerprint, outside-diff findings routed to the summary body
instead of inline, the inline-comment cap, and the always-post-a-body
guarantee even with zero findings. No GitHub calls: summarize() is a
plain function over state, posting happens in the worker afterward.
"""

from __future__ import annotations

from codeguard.config import RepoConfig, get_settings
from codeguard.pipeline.nodes import summarize
from codeguard.severity import Severity
from tests.pipeline.conftest import make_finding


def _state(findings, patches, files=None, repo_config=None):
    return {
        "owner": "o", "repo": "r", "pr_number": 1, "head_sha": "sha", "installation_id": 1,
        "repo_config": repo_config or RepoConfig(),
        "files": files or {p: "" for p in patches},
        "patches": patches,
        "tool_findings": [],
        "touches_ai_code": False,
        "findings": findings, "repo_level_findings": [],
        "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
    }


def test_summarize_dedupes_by_fingerprint():
    f1 = make_finding(file="a.py", line=5, rule_id="B105", message="same issue")
    f2 = make_finding(file="a.py", line=5, rule_id="B105", message="same issue")
    assert f1.fingerprint == f2.fingerprint  # sanity: these really are duplicates

    patches = {"a.py": "@@ -1,10 +1,10 @@\n context"}
    result = summarize(_state([f1, f2], patches))

    assert len(result["inline_findings"]) == 1
    assert "found 1 issue" in result["summary"]


def test_finding_outside_diff_goes_to_summary_body_not_inline():
    # patch only covers lines 1-5; finding at line 50 is nowhere near it.
    f = make_finding(file="a.py", line=50, rule_id="B105", message="out of range")
    patches = {"a.py": "@@ -1,5 +1,5 @@\n context"}

    result = summarize(_state([f], patches))

    assert result["inline_findings"] == []  # never dropped...
    assert "a.py:50" in result["summary"]   # ...just not inline
    assert "B105" in result["summary"]


def test_finding_inside_diff_is_inlined():
    f = make_finding(file="a.py", line=3, rule_id="B105", message="in range")
    patches = {"a.py": "@@ -1,5 +1,5 @@\n context"}

    result = summarize(_state([f], patches))

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

    result = summarize(_state(findings, patches))

    assert len(result["inline_findings"]) == cap
    inlined_ids = {f.rule_id for f in result["inline_findings"]}
    for i in range(5):
        assert f"R{i}" in inlined_ids, "a HIGH-severity finding was bumped by a LOW one"
    assert "additional finding" in result["summary"]


def test_zero_findings_still_produces_a_body():
    result = summarize(_state([], {}, files={"a.py": "", "b.py": ""}))

    assert result["inline_findings"] == []
    assert "no issues found" in result["summary"]
    assert "2 file(s)" in result["summary"]
