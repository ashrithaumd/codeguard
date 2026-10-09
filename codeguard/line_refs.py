"""Remove line numbers from a model's prose.

Every place that shows a finding already shows its location, from the
finding itself. A line number inside the model's own sentence adds nothing
and can be wrong: live on codeguard-playground the What text said "Line 43
concatenates user_input" where the prompt is built on line 44, under a
location that correctly read 44 -> 49. The agents are told not to write
them (nodes.NO_LINE_NUMBERS_RULE); this removes what gets through, at
render time, so stored reports of every vintage are covered.

Our own flow note ("Assigned at line 44, sent to the model at line 49.",
pipeline/merge.flow_note) is deterministic and correct, so it is protected
and kept verbatim.
"""

from __future__ import annotations

import re

_NUMS = r"\d+(?:(?:\s*[-–]\s*|\s*,\s*(?:and\s+)?|\s+and\s+|\s+to\s+)\d+)*"
_FLOW_NOTE = re.compile(r"Assigned at line \d+, sent to the model at line \d+\.")

_RULES: list[tuple[re.Pattern, str]] = [
    # "(line 98: random.uniform ...)" -> "(random.uniform ...)"
    (re.compile(rf"\((?:on |at |in )?[Ll]ines? {_NUMS}:\s*"), "("),
    # " (lines 21, 24 and 45)" -> ""
    (re.compile(rf"\s*\((?:on |at |in )?[Ll]ines? {_NUMS}\)"), ""),
    # " on line 13" / " at lines 3, 7 and 9" / " in line 33" -> ""
    (re.compile(rf"\s+(?:[Oo]n|[Aa]t|[Ii]n|[Ff]rom)\s+lines?\s+{_NUMS}\b"), ""),
    # "Line 12's" -> "This line's"
    (re.compile(rf"\bLine {_NUMS}'s\b"), "This line's"),
    (re.compile(rf"\bline {_NUMS}'s\b"), "this line's"),
    # "Lines 21-25" -> "These lines"; "Line 43" -> "This line"
    (re.compile(rf"\bLines {_NUMS}\b"), "These lines"),
    (re.compile(rf"\blines {_NUMS}\b"), "these lines"),
    (re.compile(rf"\bLine {_NUMS}\b"), "This line"),
    (re.compile(rf"\bline {_NUMS}\b"), "this line"),
]

_TIDY: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\(\s*\)"), ""),
    (re.compile(r"\(\s+"), "("),
    (re.compile(r"\s+([,.;:!?)])"), r"\1"),
    (re.compile(r"[ \t]{2,}"), " "),
]


def strip_line_refs(text: str | None) -> str | None:
    if not text or not re.search(r"\b[Ll]ines? \d", text):
        return text
    protected: list[str] = []

    def _protect(match: re.Match) -> str:
        protected.append(match.group(0))
        return f"\x00{len(protected) - 1}\x00"

    out = _FLOW_NOTE.sub(_protect, text)
    for pattern, replacement in _RULES:
        out = pattern.sub(replacement, out)
    for pattern, replacement in _TIDY:
        out = pattern.sub(replacement, out)
    return re.sub(r"\x00(\d+)\x00", lambda m: protected[int(m.group(1))], out).strip()
