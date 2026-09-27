"""Neutralising text on its way INTO a GitHub comment.

Every input path into this pipeline is guarded -- guardrails strips
instruction-shaped spans, redact_source removes secrets. This module is
the other direction, which had no guard at all on its two biggest
surfaces: the inline review comment body (worker/main.py) and the review
body's remainder list (pipeline/nodes.py). Both interpolate
Finding.message and Finding.rule_id raw.

WHY THAT MATTERS MORE THAN IT LOOKS. A finding message is tool-generated
but echoes the scanned code -- Bandit's hardcoded-secret message contains
the matched string literally -- and for a generative agent it is model
prose ABOUT attacker-authored code. GitHub renders a comment as Markdown.
So the interesting payload is not one that makes the model misbehave; it
is one that gets a string echoed into a comment:

  @mention   NOTIFIES A REAL PERSON. This is the only place an injection
             escapes our infrastructure entirely -- a PR author can make
             CodeGuard ping anyone on GitHub, repeatedly, from the
             operator's App, and nothing in the review has to go wrong for
             it to work.
  #1234      cross-references someone else's issue. Permanent, and
             visible to them.
  raw HTML   GitHub permits a subset in comments, <details>, <summary> and
             headings included, so a message can forge a convincing
             "CodeGuard: no issues found" inside CodeGuard's own comment.

WHAT IS DELIBERATELY NOT DONE: Markdown is not stripped or escaped.
`**bold**` in a message renders bold, and that is allowed to happen. The
goal is that our output cannot ACT -- notify, cross-link, or execute --
not that it cannot be styled. Escaping every Markdown metacharacter would
make real findings unreadable (`*args`, `_private`, backticked code) for
no security gain, since styling has no side effect.

The costs are what make each choice easy:
  * HTML-escaping is LOSSLESS in Markdown -- `&lt;` renders as `<` -- so
    it costs nothing at all.
  * Neutralising a mention costs one invisible character.
  * A length cap costs a truncated tail on a pathological message.
"""

from __future__ import annotations

import html
import re

# Long enough for any real rule_id, path or one-line message; short enough
# that a single finding cannot push the fixed sections of a report out of
# view. GitHub's own cap on a check run's output.summary is 65535
# characters, which nothing here approaches.
MAX_ONE_LINE_CHARS = 120

# A multi-line body (an inline comment) gets a far larger allowance,
# because its whole job is to explain one finding, but it is still bounded:
# a message is model or tool output, and "bounded by the agent's max_tokens"
# is not a bound -- max_tokens is a configurable setting, and raising it
# for better reviews should not silently raise this.
MAX_BODY_CHARS = 4_000

# U+200B ZERO WIDTH SPACE. Breaks GitHub's autolinker without changing what
# a reader sees. Chosen over dropping the character or backtick-wrapping:
# dropping it corrupts a finding that is ABOUT an @-name, and wrapping in a
# code span would swallow the rest of the message's formatting.
_BREAK = "​"

# `@name` and `@org/team`, wherever the @ does not follow a word
# character. That one lookbehind is what keeps an email address intact --
# `ops@example.com` has `s` before the @, and a finding about a hardcoded
# address has to still name it.
#
# It was `(?<![\w@.-])`, which also skipped an @ after a dot or a dash, and
# that was a hole: a Semgrep rule id like `rules.@torvalds.sqli` is
# interpolated into the review body, rule ids come from a rules file a
# repository supplies, and GitHub is not documented to refuse a mention
# after a dot. Caught by tests/pipeline/test_outbound_injection.py. The
# narrower lookbehind loses nothing -- an email's local part cannot end in
# a dot -- so there was no reason for the wider one.
#
# `@property` and `@staticmethod` are excluded by name: Python findings
# quote decorators constantly, they are not usernames, and mangling them
# would make every message about one read as corrupted.
_DECORATORS = frozenset({
    "property", "staticmethod", "classmethod", "abstractmethod", "override",
    "dataclass", "cached_property", "functools", "app", "pytest", "patch",
})
_MENTION = re.compile(r"(?<!\w)@([A-Za-z0-9][A-Za-z0-9-]*(?:/[A-Za-z0-9._-]+)?)")

# GitHub autolinks #<digits> and nothing else, so `#fff` and `#section`
# are left alone rather than mangled.
_ISSUE_REF = re.compile(r"(?<![\w&])#(\d+)")


def _neutralise_links(text: str) -> str:
    def _mention(match: re.Match[str]) -> str:
        name = match.group(1)
        if name.split("/")[0].lower() in _DECORATORS:
            return match.group(0)
        return f"@{_BREAK}{name}"

    text = _MENTION.sub(_mention, text)
    return _ISSUE_REF.sub(lambda m: f"#{_BREAK}{m.group(1)}", text)


def _truncate(text: str, limit: int) -> str:
    """Cap the length without leaving a half-written HTML entity.

    Cutting `&amp;` in the middle leaves `&am`, which renders as literal
    text rather than `&`. Cosmetic, but it looks like corruption in a
    report, and a report that looks corrupted does not get read.
    """
    if len(text) <= limit:
        return text
    cut = text[:limit]
    tail = cut.rfind("&")
    if tail != -1 and ";" not in cut[tail:]:
        cut = cut[:tail]
    return cut + "…"


def escape_for_github(text: str | None) -> str:
    """Neutralise one string for a multi-line GitHub comment body.

    HTML-escaped (lossless, see the module docstring), mentions and issue
    references defused, length bounded. Newlines are KEPT: an inline
    comment body is not a table cell, and a tool message with real
    structure should keep it -- only the parts that act are removed.
    """
    if not text:
        return ""
    escaped = html.escape(str(text), quote=False)
    return _truncate(_neutralise_links(escaped), MAX_BODY_CHARS)


def escape_one_line(text: str | None) -> str:
    """The same, for somewhere a newline would break the layout.

    Two extra jobs. Whitespace is collapsed, because the review body's
    remainder list is one finding per line and a message containing a
    newline would both break the list and be able to forge a heading on
    the line it created. And a pipe becomes its entity, because a raw `|`
    silently splits a Markdown table row into extra cells.

    Truncation runs last, so the cap applies to what is actually emitted.
    """
    if not text:
        return ""
    flattened = " ".join(str(text).split())
    escaped = html.escape(flattened, quote=False).replace("|", "&#124;")
    return _truncate(_neutralise_links(escaped), MAX_ONE_LINE_CHARS)
