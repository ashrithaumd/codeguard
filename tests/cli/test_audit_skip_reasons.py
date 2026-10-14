"""Every skipped file is reported under the reason it was ACTUALLY skipped for.

The incomplete list and the raw report's Skipped section used to say every
skipped file was "dropped by the audit budget ceiling" -- true when the
budget was the only way to be skipped, wrong once invalid workflows,
oversized files, oversized lockfiles and the AI review cap joined the same
list. A Python audit that only hits the budget must read exactly as before.
"""

from __future__ import annotations

from codeguard.cli import build_report_data, render_report
from codeguard.tools.zizmor_runner import INVALID_YAML

BUDGET_INCOMPLETE = "{n} file(s) were never scanned — dropped by the audit budget ceiling before any tool ran"
BUDGET_HEADER = "**{n} file(s) never scanned** (dropped by the audit budget before any tool ran):"

MIXED = [
    ("big/a.py", "dropped by audit_max_files_ceiling"),
    ("big/b.py", "dropped by audit_max_tokens_ceiling"),
    (".github/workflows/nightly.yml", INVALID_YAML),
    ("web/vendor.bundle.js", "too large to scan (over 256 KB)"),
    ("web/package-lock.json", "not checked for known vulnerabilities (over 20 MB)"),
    ("src/many.ts", "not reviewed by AI (cap: 40 files)"),
    ("src/dense.ts", "3 finding(s) not reviewed by AI (cap: 10 per file)"),
]


def _kwargs(skipped):
    return dict(
        target="https://github.com/acme/widgets", files_scanned=3, files_ai_aware=0,
        ai_reviewed_findings=[], passthrough_findings=[], dismissed=[], eval_hygiene_findings=[],
        osv_findings=[], skipped_files=skipped, verdict_call_failures=[], unavailable_tools=[],
        tokens_in=10, tokens_out=5, estimated_cost_usd=0.01, elapsed_s=1.0,
    )


def test_budget_only_reads_exactly_as_before():
    skipped = MIXED[:2]
    assert build_report_data(**_kwargs(skipped))["incomplete"] == [BUDGET_INCOMPLETE.format(n=2)]
    report = render_report(**_kwargs(skipped))
    assert (BUDGET_HEADER.format(n=2) + "\n\n- `big/a.py`: dropped by audit_max_files_ceiling\n"
            "- `big/b.py`: dropped by audit_max_tokens_ceiling\n") in report


def test_each_reason_is_counted_under_its_own_line():
    assert build_report_data(**_kwargs(MIXED))["incomplete"] == [
        BUDGET_INCOMPLETE.format(n=2),
        "1 file(s) were never scanned — too large to scan",
        "1 workflow file(s) were not scanned — invalid YAML",
        "1 lockfile(s) were not checked for known vulnerabilities — too large",
        "2 file(s) had findings not reviewed by AI — the review cap was reached, so they are reported unverified",
    ]


def test_raw_report_groups_files_under_their_reason():
    report = render_report(**_kwargs(MIXED))
    assert BUDGET_HEADER.format(n=2) in report
    for header, path in [
        ("**1 file(s) never scanned** (too large to scan):", "web/vendor.bundle.js"),
        ("**1 workflow file(s) not scanned** (invalid YAML):", ".github/workflows/nightly.yml"),
        ("**1 lockfile(s) not checked for known vulnerabilities** (too large):", "web/package-lock.json"),
        ("**2 file(s) with findings not reviewed by AI** (the review cap was reached; reported unverified):",
         "src/many.ts"),
    ]:
        assert header in report
        # The file is listed under its own header, before the next one.
        section = report.split(header, 1)[1].split("**", 1)[0]
        assert f"`{path}`" in section
    # Nothing that was not budget is called budget.
    budget_section = report.split(BUDGET_HEADER.format(n=2), 1)[1].split("**", 1)[0]
    assert "nightly.yml" not in budget_section and "vendor.bundle.js" not in budget_section


def test_no_budget_skip_means_no_budget_wording():
    skipped = [(".github/workflows/nightly.yml", INVALID_YAML), ("web/vendor.bundle.js", "too large to scan (over 256 KB)")]
    data = build_report_data(**_kwargs(skipped))
    assert not any("budget" in r for r in data["incomplete"])
    assert "budget" not in render_report(**_kwargs(skipped)).split("## Skipped", 1)[1]


def test_an_unknown_reason_is_still_counted_and_not_called_budget():
    data = build_report_data(**_kwargs([("x.bin", "something new")]))
    assert data["incomplete"] == ["1 file(s) were not fully scanned"]


def test_a_multi_line_rule_message_is_one_list_item_in_the_raw_report():
    # GitLab's go_unsafe_rule-unsafe message is a multi-line description with
    # its own "- [link]" bullets; printed as-is it broke the findings list.
    from codeguard.pipeline.models import DismissedFinding
    from codeguard.severity import Severity
    from codeguard.tools.models import Finding

    message = "The `unsafe` package allows low-level access.\nThis includes pointers.\n\n- [Buffer overflows](https://x)\n  which\ncan lead to code execution."
    kwargs = _kwargs([("big/a.py", "dropped by audit_max_files_ceiling\n(over the cap)")])
    kwargs["passthrough_findings"] = [Finding.create(file="now_windows.go", start_line=26, end_line=26, severity=Severity.LOW,
                                                     source_tool="gitlab-sast", rule_id="go_unsafe_rule-unsafe", message=message)]
    kwargs["dismissed"] = [DismissedFinding(file="a.go", start_line=3, rule_id="r", reason="Jitter only.\nNothing secret.")]
    report = render_report(**kwargs)
    one = ("The `unsafe` package allows low-level access. This includes pointers. - [Buffer overflows](https://x) "
           "which can lead to code execution.")
    assert f"[go_unsafe_rule-unsafe] {one}" in report
    assert "[r] Jitter only. Nothing secret." in report
    assert "dropped by audit_max_files_ceiling (over the cap)" in report
    # No list item spills onto a following line.
    assert "\nThis includes pointers." not in report and "\ncan lead to code execution." not in report
