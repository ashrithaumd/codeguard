"""One bug, one finding: merge what two tools said about the same line.

Bandit and the LLM-security ruleset overlap on purpose -- Bandit is
generic Python security, the ruleset is the LLM-specific reading of the
same sinks -- so `eval(completion.choices[0].message.content)` is B307 AND
llm-output-to-dangerous-sink. Reported twice, it reads as two problems
(codeguard-playground assistant.py:64 did exactly that).

MERGED ONLY WHEN THE RULES ARE KNOWN EQUIVALENTS, never merely because
they share a line. Line 33 of the same file carries a missing timeout and
a missing max_tokens; those are two bugs with two fixes, and folding them
together would hide one. The groups below are the pairs where both rules
describe the same defect at the same sink.
"""

from __future__ import annotations

from codeguard.tools.models import Finding

# Each set is one defect as seen by different rules. Bare rule ids:
# Semgrep's arrive prefixed with the rules directory ("rules.llm-...").
_EQUIVALENT = (
    # Model output (or anything) executed: eval/exec, a shell.
    frozenset({"B307", "B102", "B602", "B605", "llm-output-to-dangerous-sink"}),
    # SQL built from a string.
    frozenset({"B608", "llm-output-to-sql"}),
    # A hardcoded credential.
    frozenset({"B105", "B106", "B107", "llm-hardcoded-api-key", "llm-langchain-hardcoded-api-key"}),
)


def bare_rule_id(rule_id: str) -> str:
    return rule_id.rsplit(".", 1)[-1]


def rule_label(f: Finding) -> str:
    """Every rule behind a finding, for display: a merged finding lists
    each source, an unmerged one its own rule id."""
    return ", ".join(f.sources) if f.sources else f.rule_id


def flow_note(f: Finding) -> str:
    """Where a taint finding's value was BUILT, when that is not the line
    it was reported on (the sink): "Assigned at line 44, sent to the model
    at line 49." Empty for every other finding."""
    if not f.source_line or f.source_line == f.start_line:
        return ""
    return f"Assigned at line {f.source_line}, sent to the model at line {f.start_line}."


def with_flow_note(message: str, f: Finding) -> str:
    """`message` plus the flow note, once."""
    note = flow_note(f)
    if not note or note in message:
        return message
    return f"{message} {note}".strip()


def _group_of(rule_id: str) -> int | None:
    bare = bare_rule_id(rule_id)
    for i, group in enumerate(_EQUIVALENT):
        if bare in group:
            return i
    return None


def _richness(f: Finding) -> tuple:
    """Which finding of a merged set speaks for it: the most severe, then
    the one with structured text, then the longer message."""
    return (f.severity, bool(f.what or f.why or f.fix), len(f.message))


def merge_same_bug(findings: list[Finding]) -> list[Finding]:
    """Merge findings on the same file and line whose rules are known
    equivalents. The merged finding keeps the most informative member's
    text, the highest severity of any member, and every member's rule id
    in `sources` (primary first). Order of first appearance is kept."""
    buckets: dict[tuple, list[Finding]] = {}
    order: list[tuple] = []
    for f in findings:
        group = _group_of(f.rule_id)
        key = (f.file, f.start_line, group) if group is not None else (id(f),)
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(f)

    merged: list[Finding] = []
    for key in order:
        members = buckets[key]
        if len(members) == 1:
            merged.append(members[0])
            continue
        primary = max(members, key=_richness)
        sources = [bare_rule_id(primary.rule_id)] + sorted(
            {bare_rule_id(m.rule_id) for m in members} - {bare_rule_id(primary.rule_id)}
        )
        merged.append(primary.model_copy(update={
            "severity": max(m.severity for m in members),
            "sources": sources,
        }))
    return merged
