"""The review graph's impact node, and the summary section it feeds.

The worker computes state["impact_report"] before the graph runs
(codeguard/pipeline/impact.py over the repository's files from
codeguard/github/tarball.py), only when Settings.impact_analysis_enabled
and the repo's own enable_impact_analysis are both on. This node turns it
into review output:

  SIGNATURE (deterministic, no model call)
    * a HIGH finding on the changed def's line -- in the diff, so it can be
      an inline comment -- naming every caller that no longer fits
    * a HIGH finding at a broken call that is itself on a line this PR
      changed (also in the diff)
    * a summary line per caller outside the diff

  BEHAVIOUR (one model call per PR, at most)
    * only for symbols whose body changed, never for removed ones
    * given before/after source and the chosen call sites, capped at
      MAX_CONTEXT_CHARS, and asked which callers rely on what changed
    * a concern is kept only for a call site it was actually shown

WHERE IT IS POSTED. GitHub refuses inline comments outside the diff, so a
caller in an unchanged file can only be in the review body: the "Callers
outside this diff" section, each linked to its line at the PR head.
"""

from __future__ import annotations

import logging
from urllib.parse import quote

from codeguard.config import get_settings
from codeguard.github.outbound import escape_one_line
from codeguard.pipeline.impact import CallSite, ChangedSymbol, ImpactReport
from codeguard.pipeline.llm_call import call_agent
from codeguard.pipeline.nodes import _parse_json_array, _repo_context
from codeguard.severity import Severity
from codeguard.tools.models import Finding

logger = logging.getLogger(__name__)

IMPACT_SECTION_TITLE = "Callers outside this diff"
MAX_CONTEXT_CHARS = 24_000
_MAX_CONCERN_CHARS = 300

_IMPACT_SYSTEM_PROMPT = """You check whether the callers of changed Python functions still work. For each changed function you get its source before and after the change, and some of its call sites elsewhere in the repository, each labelled path:line. Signature mismatches (missing or unexpected arguments) are already checked by a tool; do not report them.

Report a call site only when the code shown there depends on behaviour the change altered: a return value or type it uses, an exception it catches or relies on being raised, a side effect, a default, an ordering or a unit. Say what changed and what at that call site breaks, in one sentence, without line numbers. Do not report style, possible future problems, or call sites that are fine. A site marked "possible" may not call this function at all; only report it if the code shown makes that clear.

Respond with only a JSON array, no prose and no code fence: [{"site": "path:line", "symbol": "name", "concern": "..."}]. Respond with [] if no call site is affected."""


# --------------------------------------------------------------------------
# The node
# --------------------------------------------------------------------------

def _caller(site: CallSite, kind: str, note: str) -> dict:
    return {"path": site.path, "line": site.line, "qualname": site.qualname, "kind": kind,
            "note": note, "in_diff": site.in_diff}


def _signature_findings(report: ImpactReport) -> list[Finding]:
    by_symbol: dict[str, list[CallSite]] = {}
    for site in report.sites:
        if site.mismatch:
            by_symbol.setdefault(site.qualname, []).append(site)

    findings: list[Finding] = []
    for sym in report.symbols:
        broken = by_symbol.get(sym.qualname)
        if not broken:
            continue
        listed = "; ".join(f"{s.path}:{s.line} ({s.mismatch})" for s in broken)
        if sym.kind != "removed":
            findings.append(Finding.create(
                file=sym.path, start_line=sym.line, end_line=sym.line, severity=Severity.HIGH,
                source_tool="impact", rule_id="impact.signature",
                message=f"{len(broken)} caller(s) of `{sym.qualname}` no longer match its new signature: {listed}",
                title=f"Callers of `{sym.qualname}` no longer match its signature",
                what=f"{len(broken)} existing call(s) elsewhere in the repository will fail: {listed}.",
                why="Each of those calls raises TypeError at runtime the first time it runs.",
                fix="Update those callers in this PR, or give the new parameter a default.",
            ))
        for site in broken:
            if site.in_diff:
                findings.append(Finding.create(
                    file=site.path, start_line=site.line, end_line=site.end_line, severity=Severity.HIGH,
                    source_tool="impact", rule_id="impact.signature",
                    message=f"This call to `{sym.qualname}` no longer matches its signature: {site.mismatch}.",
                    title=f"Call to `{sym.qualname}` does not match its new signature",
                    what=f"{site.mismatch}.", why="This call raises TypeError at runtime.",
                    fix=f"Pass the arguments `{sym.qualname}` now takes.",
                ))
    return findings


def _behavior_prompt(symbols: list[ChangedSymbol], sites: list[CallSite]) -> tuple[str, set[str]]:
    """The user content, capped at MAX_CONTEXT_CHARS, and the site keys it
    actually contains (a concern about any other site is dropped)."""
    parts: list[str] = []
    shown: set[str] = set()
    used = 0
    for sym in symbols:
        sym_sites = [s for s in sites if s.qualname == sym.qualname]
        if not sym_sites:
            continue
        head = (f"### `{sym.qualname}` in {sym.path}\n\nBefore:\n```python\n{sym.base_source}\n```\n\n"
                f"After:\n```python\n{sym.head_source}\n```\n\nCall sites:\n")
        if used + len(head) > MAX_CONTEXT_CHARS:
            break
        parts.append(head)
        used += len(head)
        for site in sym_sites:
            key = f"{site.path}:{site.line}"
            block = f"\n{key} ({'resolved' if site.resolved else 'possible'})\n```python\n{site.snippet}\n```\n"
            if used + len(block) > MAX_CONTEXT_CHARS:
                break
            parts.append(block)
            used += len(block)
            shown.add(key)
    return "".join(parts), shown


def review_impact(state) -> dict:
    report: ImpactReport | None = state.get("impact_report")
    if not report or not report.symbols:
        return {}

    callers = [_caller(s, "signature", s.mismatch) for s in report.sites if s.mismatch]
    out: dict = {"findings": _signature_findings(report), "impact_callers": callers}

    behavior_symbols = [s for s in report.symbols if s.body_changed and s.kind != "removed"]
    context_sites = [s for s in report.sites if any(s.qualname == b.qualname for b in behavior_symbols)]
    if not context_sites:
        return out

    content, shown = _behavior_prompt(behavior_symbols, context_sites)
    if not shown:
        return out
    settings = get_settings()
    result = call_agent(
        agent="impact", api_key=settings.anthropic_api_key, system_prompt=_IMPACT_SYSTEM_PROMPT,
        repo_context=_repo_context(state["owner"], state["repo"]), user_content=content,
        model=settings.impact_agent_model, max_tokens=settings.impact_agent_max_tokens,
        timeout=settings.impact_agent_timeout_s, temperature=0,
    )
    out["node_latencies"] = [{"node": "review_impact", "file": "", "seconds": result.latency_s}]
    if not result.ok:
        logger.warning("impact behaviour call failed for %s/%s#%s (%s)",
                       state["owner"], state["repo"], state.get("pr_number"), result.error)
        out["impact_notes"] = [f"behavior check unavailable ({result.error})"]
        return out

    out.update(tokens_in=result.tokens_in, tokens_out=result.tokens_out,
               estimated_cost_usd=result.estimated_cost_usd)
    by_key = {f"{s.path}:{s.line}": s for s in context_sites}
    known = {b.qualname for b in behavior_symbols}
    for item in _parse_json_array(result.raw_text, "impact", "impact"):
        key, concern = str(item.get("site", "")), str(item.get("concern", "")).strip()
        site = by_key.get(key)
        if key not in shown or site is None or not concern or str(item.get("symbol", site.qualname)) not in known:
            continue
        callers.append(_caller(site, "behavior", concern[:_MAX_CONCERN_CHARS]))
    return out


# --------------------------------------------------------------------------
# The summary section
# --------------------------------------------------------------------------

def _line_url(state, path: str, line: int) -> str:
    return (f"https://github.com/{state['owner']}/{state['repo']}/blob/{state['head_sha']}/"
            f"{quote(path, safe='/')}#L{line}")


def render_impact_section(state) -> list[str]:
    """Markdown lines for the review body, or [] when there is nothing to
    say. Every piece of text that came from the repository or the model
    goes through escape_one_line."""
    report: ImpactReport | None = state.get("impact_report")
    notes = state.get("impact_notes") or []
    callers = [c for c in state.get("impact_callers") or [] if not c.get("in_diff")]

    lines: list[str] = []
    for note in notes:
        if note.startswith("skipped"):
            lines.append(f"Impact analysis {escape_one_line(note)}.")
    for c in callers:
        location = f"{c['path']}:{c['line']}"
        lines.append(
            f"- [`{escape_one_line(location)}`]({_line_url(state, c['path'], c['line'])}) calls "
            f"`{escape_one_line(c['qualname'])}` ({c['kind']}): {escape_one_line(c['note'])}"
        )
    if report and report.omitted:
        lines.append(f"- {report.omitted} more call site(s) not shown.")
    if report and report.dynamic_refs:
        counts = ", ".join(f"`{escape_one_line(name)}` ×{n}" for name, n in sorted(report.dynamic_refs.items()))
        total = sum(report.dynamic_refs.values())
        lines.append(f"{total} dynamic reference(s) not analysed (getattr, callbacks, registries): {counts}.")
    for note in notes:
        if note.startswith("behavior check unavailable"):
            lines.append(f"Behaviour check unavailable for this review: {escape_one_line(note)}.")

    if not lines:
        return []
    return ["", f"**{IMPACT_SECTION_TITLE}**", *lines]
