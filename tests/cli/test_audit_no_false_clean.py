"""An audit must never report "clean" when it did not look.

THE DEFECT THIS REPRODUCES
-------------------------
render_report ends with:

    if not all_findings:
        lines.append("No findings.")

unconditionally. So an audit that examined almost nothing produces a
report whose headline reads "0 finding(s) across N scanned file(s)" and
whose body reads "No findings." -- which is what somebody screenshots.

Three ways to get there, in increasing severity:

1. FILES DROPPED BY THE BUDGET. Already noted at the top of the report,
   but "No findings." still appears below it, and the note is a **Note**
   while the absence of findings is the thing a reader remembers.

2. EVERY AI VERDICT CALL FAILED. Recorded under Skipped, same problem.

3. NO SCANNER RAN AT ALL, and this one is invisible. run_tools_on_files
   emits a meta-finding per unavailable tool (UNAVAILABLE_RULE_ID) with
   file="<pr>", and the audit's own passthrough filter drops it:

       claimed_bandit_files = {f.file for f in tool_findings
                               if f.source_tool == "bandit"}

   "<pr>" is in that set, so a bandit-unavailable meta-finding counts as
   "claimed by the verdict layer" and is filtered out -- while the verdict
   layer never saw it either, because security_findings_by_file is keyed by
   real paths. The PR path surfaces these with a [!CAUTION] via
   check_summary.unavailable_tools(); the audit path never calls it.

   So an audit run in an image without bandit and semgrep reports "No
   findings." over a repository full of SQL injection.

WHAT A CLEAN RESULT HAS TO MEAN: every tool ran, every file was scanned,
every verdict call answered. Anything less is a partial result, and the
report has to say so where the finding count is, not in a note above it.
"""

from __future__ import annotations

from codeguard.cli import render_report
from codeguard.severity import Severity
from codeguard.tools.base import UNAVAILABLE_RULE_ID
from codeguard.tools.models import Finding

CLEAN_PHRASE = "No findings."


def _report(**over):
    kwargs = dict(
        target="https://github.com/acme/widgets",
        files_scanned=3, files_ai_aware=0,
        ai_reviewed_findings=[], passthrough_findings=[],
        dismissed=[], eval_hygiene_findings=[], osv_findings=[],
        skipped_files=[], verdict_call_failures=[], unavailable_tools=[],
        tokens_in=10, tokens_out=5, estimated_cost_usd=0.01, elapsed_s=1.0,
    )
    kwargs.update(over)
    return render_report(**kwargs)


def _unavailable(tool):
    return Finding.create(
        file="<pr>", start_line=0, end_line=0, severity=Severity.LOW,
        source_tool=tool, rule_id=UNAVAILABLE_RULE_ID,
        message=f"{tool} unavailable: not found on PATH",
    )


# --- the three incomplete runs ------------------------------------------


def test_a_report_with_files_dropped_does_not_claim_to_be_clean():
    report = _report(skipped_files=[("big.py", "over the token ceiling")])

    assert CLEAN_PHRASE not in report
    assert "not a clean result" in report.lower()
    assert "big.py" in report


def test_a_report_with_failed_verdict_calls_does_not_claim_to_be_clean():
    report = _report(verdict_call_failures=[("a.py", "timeout")])

    assert CLEAN_PHRASE not in report
    assert "not a clean result" in report.lower()


def test_a_report_with_an_unavailable_tool_does_not_claim_to_be_clean():
    """The invisible one. A tool that did not run means the rules it owns
    were never applied, and no number of zero findings says otherwise."""
    report = _report(unavailable_tools=["bandit"])

    assert CLEAN_PHRASE not in report
    assert "not a clean result" in report.lower()
    assert "bandit" in report


def test_the_unavailable_tool_is_named_where_a_reader_will_see_it():
    """Not only in a section at the bottom. The claim being corrected is
    the finding count, so the correction belongs next to it."""
    report = _report(unavailable_tools=["bandit", "semgrep"])
    head = report.split("## ")[0]

    assert "bandit" in head and "semgrep" in head


# --- the clean run still reads clean ------------------------------------


def test_a_genuinely_complete_run_says_no_findings():
    """The precision guard. If "not clean" were shown unconditionally the
    tests above would pass while the report became useless."""
    report = _report()

    assert CLEAN_PHRASE in report
    assert "not a clean result" not in report.lower()


def test_a_complete_run_with_findings_is_unaffected():
    finding = Finding.create(
        file="a.py", start_line=1, end_line=1, severity=Severity.HIGH,
        source_tool="bandit", rule_id="B608", message="sqli",
    )
    report = _report(passthrough_findings=[finding])

    assert CLEAN_PHRASE not in report  # there ARE findings
    assert "not a clean result" not in report.lower()
    assert "B608" in report


def test_findings_plus_an_unavailable_tool_still_warns():
    """Findings do not make a partial run complete: the tool that did not
    run owns rules that nothing else checked."""
    finding = Finding.create(
        file="a.py", start_line=1, end_line=1, severity=Severity.HIGH,
        source_tool="ruff", rule_id="E501", message="line too long",
    )
    report = _report(passthrough_findings=[finding], unavailable_tools=["bandit"])

    assert "not a clean result" in report.lower()


# --- the wiring: the meta-finding must reach the report at all ----------


def test_the_unavailable_meta_finding_is_not_swallowed_by_the_filter():
    """The bug that made case 3 invisible.

    The audit's passthrough filter treats any bandit finding whose file is
    in claimed_bandit_files as claimed by the verdict layer -- and "<pr>",
    the meta-finding's file, is in that set because the meta-finding itself
    put it there. So it was dropped by the filter AND never seen by the
    verdict layer, which is keyed on real paths.
    """
    from codeguard.cli import _audit_unavailable_tools

    tool_findings = [_unavailable("bandit"), _unavailable("semgrep")]
    assert _audit_unavailable_tools(tool_findings) == ["bandit", "semgrep"]


def test_a_real_finding_is_not_mistaken_for_an_unavailable_tool():
    real = Finding.create(
        file="a.py", start_line=1, end_line=1, severity=Severity.HIGH,
        source_tool="bandit", rule_id="B608", message="sqli",
    )
    from codeguard.cli import _audit_unavailable_tools

    assert _audit_unavailable_tools([real]) == []


# --- the outcome, not just the wording ----------------------------------


def test_no_scanner_at_all_is_not_a_completed_audit():
    """The wording in the report is necessary but not sufficient.

    A stored audit's STATUS is what the repositories page shows and what
    anyone querying the table sees. If every deterministic tool was
    unavailable, the audit's entire security coverage is zero -- the
    verdict agents only ever review tool findings -- so "done" would be a
    lie told in a machine-readable field, where no warning text reaches.

    FAILED rather than REJECTED: rejected means we declined and retrying
    unchanged will not help, and this is an image or PATH problem that a
    retry WILL fix once it is corrected.
    """
    from codeguard.cli import ALL_SCANNERS, _scanner_coverage_lost

    assert _scanner_coverage_lost(sorted(ALL_SCANNERS)) is True
    assert _scanner_coverage_lost(["bandit"]) is False
    assert _scanner_coverage_lost([]) is False


def test_the_scanner_list_matches_what_actually_runs():
    """ALL_SCANNERS has to stay in step with tools/run_all.RUNNERS, or a
    fourth tool would make "every scanner failed" unreachable -- the check
    would quietly stop firing."""
    from codeguard.cli import ALL_SCANNERS
    from codeguard.tools.run_all import RUNNERS

    names = {runner.__name__.removeprefix("run_") for runner in RUNNERS}
    assert names == ALL_SCANNERS, (
        f"ALL_SCANNERS is {sorted(ALL_SCANNERS)} but RUNNERS provides {sorted(names)}"
    )
