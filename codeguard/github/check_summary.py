"""The Check Run's summary body — the at-a-glance panel GitHub renders
in the PR's merge box, next to the pass/fail the gate already decided.

Deliberately NOT an LLM call. This is the one surface a reviewer reads
before deciding whether to trust the review at all, so it must say the
same thing every time for the same inputs, cost nothing, and never fail:
fixed templates over computed values, nothing generated. The Haiku
summary intro in pipeline/nodes.py is the opposite trade-off on purpose
(prose, aggregate counts only, allowed to vary) and lives in the PR
Review body, not here.

Everything interpolated from a Finding goes through escape_finding_text()
first, per migrations/006_reviews.sql's blanket rule: `file`, `rule_id`
and `message` are tool-generated but echo the scanned code (Bandit's
hardcoded-secret message includes the matched string literally), so they
are PR-author-influenceable. GitHub sanitises its own markdown rendering,
but a finding carrying a `|` would still silently wreck a table here,
which is reason enough to neutralise it on the way out.
"""

from __future__ import annotations

import html

from codeguard.pipeline.reviews import classify_findings
from codeguard.severity import Severity
from codeguard.tools.base import UNAVAILABLE_RULE_ID
from codeguard.tools.models import Finding

# Long enough for any real rule_id or path, short enough that a finding
# cannot push the fixed sections out of view. GitHub's own cap on
# output.summary is 65535 characters; nothing here approaches it.
MAX_FIELD_CHARS = 120

_SEVERITY_ROWS = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)

# Labels for pipeline/reviews.py's trust buckets, which stay the single
# source of truth for the classification itself — re-deriving it from
# source_tool here is exactly the drift migrations/006_reviews.sql's
# schema comment warns about.
_BUCKET_LABELS = (
    ("verdict_confirmed", "Confirmed by an LLM verdict"),
    ("generative", "Proposed by an LLM (capped MEDIUM)"),
    ("deterministic", "Deterministic tool, no verdict layer"),
    ("unverified", "Unverified"),
)


def escape_finding_text(text: str) -> str:
    """Neutralises one finding-derived string for markdown output.

    Three separate jobs: HTML-escape (the sanitiser surface), replace
    pipes with their entity (a raw `|` silently breaks a markdown table
    row into extra cells), and flatten newlines (same reason — a table
    cell cannot span lines). Truncated last, so the cap applies to what
    is actually emitted.
    """
    flattened = " ".join(str(text).split())
    escaped = html.escape(flattened, quote=False).replace("|", "&#124;")
    if len(escaped) > MAX_FIELD_CHARS:
        return escaped[:MAX_FIELD_CHARS] + "…"
    return escaped


def unavailable_tools(tool_findings: list[Finding]) -> list[str]:
    """Tools that did not run, read from the raw tool findings rather
    than the pipeline's output.

    It has to be the raw list: run_tool_on_pr emits its
    "tool unavailable" meta-finding against file="<pr>", and every
    pipeline node selects findings by `f.file == path` over real reviewed
    paths, so the meta-finding matches nothing and is dropped before
    final_state. It reaches neither the review body nor the reviews row.
    worker/main.py's own `tool_findings` is the last place it exists.
    """
    return sorted({f.source_tool for f in tool_findings if f.rule_id == UNAVAILABLE_RULE_ID})


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts = {severity: 0 for severity in _SEVERITY_ROWS}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _warning_lines(
    *, budget_exceeded: bool, files_seen: int, files_reviewed: int, missing_tools: list[str],
) -> list[str]:
    """Both warnings say the same underlying thing — this result is
    narrower than it looks — so they lead, before any count a reader
    might otherwise take at face value.

    The bold sentence carries the whole message on its own, because
    GitHub's `[!WARNING]` alert syntax degrades to a plain blockquote
    wherever it is not supported.
    """
    lines: list[str] = []
    if budget_exceeded:
        lines += [
            "> [!WARNING]",
            f"> **Diff truncated — only {files_reviewed} of {files_seen} changed file(s) were reviewed.**",
            "> The rest exceeded `max_files_per_pr` / `max_tokens_per_pr` and were not looked at.",
            "> Everything below describes the reviewed portion only.",
            "",
        ]
    for tool in missing_tools:
        lines += [
            "> [!CAUTION]",
            f"> **`{escape_finding_text(tool)}` did not run — its findings are missing entirely.**",
            "> This is not a clean result for the rules that tool owns. See the worker log for the cause.",
            "",
        ]
    return lines


def _economics_lines(*, tokens_in: int, tokens_out: int, estimated_cost_usd: float, duration_s: float) -> list[str]:
    return [
        f"- Cost: **${estimated_cost_usd:.4f}** ({tokens_in:,} in / {tokens_out:,} out tokens)",
        f"- Duration: **{duration_s:.1f}s**",
    ]


def render_check_summary(
    *,
    findings: list[Finding],
    tool_findings: list[Finding],
    blocking: list[Finding],
    gate_threshold: Severity,
    files_seen: int,
    files_reviewed: int,
    budget_exceeded: bool,
    fix_suggestion_count: int,
    dismissed_count: int,
    tokens_in: int,
    tokens_out: int,
    estimated_cost_usd: float,
    duration_s: float,
) -> str:
    """`findings` is the suppressed-excluded set the gate itself reads,
    so the tables and the pass/fail can never describe different data.
    `blocking` is that same set filtered to gate_threshold, computed once
    by worker/main.py's _check_run_conclusion and passed in rather than
    re-derived here.
    """
    missing_tools = unavailable_tools(tool_findings)
    lines = _warning_lines(
        budget_exceeded=budget_exceeded, files_seen=files_seen,
        files_reviewed=files_reviewed, missing_tools=missing_tools,
    )

    # Zero findings gets a sentence, not four empty table rows. The
    # warnings above still stand: "no findings" over a truncated diff or
    # a tool that never ran is precisely the reading to interrupt.
    if not findings:
        lines.append(f"**No findings.** {files_reviewed} of {files_seen} changed file(s) reviewed.")
        lines.append("")
        lines += _economics_lines(
            tokens_in=tokens_in, tokens_out=tokens_out,
            estimated_cost_usd=estimated_cost_usd, duration_s=duration_s,
        )
        return "\n".join(lines)

    counts = _severity_counts(findings)
    lines.append(
        f"**{len(findings)} finding(s)** across {files_reviewed} of {files_seen} changed file(s) reviewed."
    )
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | ---: |")
    for severity in _SEVERITY_ROWS:
        lines.append(f"| {severity.name.title()} | {counts[severity]} |")
    lines.append("")

    buckets = classify_findings(findings)
    lines.append("| Verification | Count |")
    lines.append("| --- | ---: |")
    for key, label in _BUCKET_LABELS:
        lines.append(f"| {label} | {buckets[key]} |")
    lines.append("")

    lines.append(f"- Fix suggestions proposed: **{fix_suggestion_count}**")
    lines.append(f"- Checked by an agent and dismissed: **{dismissed_count}**")
    lines += _economics_lines(
        tokens_in=tokens_in, tokens_out=tokens_out,
        estimated_cost_usd=estimated_cost_usd, duration_s=duration_s,
    )
    lines.append("")

    if blocking:
        worst = max(blocking, key=lambda f: f.severity)
        location = f"{escape_finding_text(worst.file)}:{worst.start_line}"
        lines.append(
            f"Gate: **{len(blocking)}** finding(s) at or above **{gate_threshold.name}**. "
            f"Worst: `{escape_finding_text(worst.source_tool)}/{worst.severity.name}` "
            f"`{escape_finding_text(worst.rule_id)}` at `{location}`."
        )
    else:
        lines.append(f"Gate: no finding at or above **{gate_threshold.name}**.")
    lines.append("")
    lines.append("See the PR Review comments for each finding in context.")

    return "\n".join(lines)
