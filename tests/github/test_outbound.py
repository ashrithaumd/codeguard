"""What we post to GitHub is output, and output has effects.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
Every input path is guarded: guardrails.neutralize_injections strips
instruction-shaped spans before the prompt is built, redact_source removes
secrets, and the check-run summary escapes every finding-derived string
through escape_finding_text.

The two BIGGEST outbound surfaces escape nothing at all.

    worker/main.py:238   body = f"**[{f.source_tool} / {f.severity.name}] "
                                f"{f.rule_id}**\\n\\n{f.message}"
    pipeline/nodes.py     body_lines.append(f"- {loc} [{tool}/{sev}] "
                                           f"{rule_id}: {message}")

`message` is tool-generated but echoes the scanned code (Bandit's
hardcoded-secret message contains the matched string literally), and for a
generative agent it is MODEL PROSE about attacker-authored code. Both are
posted into a GitHub comment, which GitHub renders as Markdown. So:

  * `@someone` in a finding message NOTIFIES A REAL PERSON. This is the
    one place a prompt injection escapes our infrastructure entirely: the
    payload does not have to make our model do anything interesting, only
    get a string echoed into a comment. A PR author can make CodeGuard
    ping anyone on GitHub, repeatedly, from the operator's App.
  * `#1234` creates a CROSS-REFERENCE on someone else's issue, which is
    permanent and visible to them.
  * GitHub allows a subset of raw HTML in comments, including <details>,
    <summary> and headings, so a message can forge structure -- a
    convincing "CodeGuard: no issues found" inside CodeGuard's own
    comment.

The treatment is asymmetric on purpose. HTML-escaping is LOSSLESS here --
`&lt;` renders as `<` in Markdown -- so it costs nothing. Neutralising a
mention costs one invisible character. Rewriting the message's Markdown
would cost readability, so it is not attempted: the goal is that our
output cannot ACT, not that it cannot be styled.
"""

from __future__ import annotations

from codeguard.github.outbound import (
    MAX_ONE_LINE_CHARS,
    escape_for_github,
    escape_one_line,
)


# --- mentions: the payload that leaves our infrastructure ---------------


def test_a_mention_is_not_a_mention_any_more():
    out = escape_for_github("see @torvalds about this")
    assert "@torvalds" not in out
    assert "torvalds" in out, "the text must still be readable"


def test_every_mention_in_one_string_is_neutralised():
    out = escape_for_github("@a and @b and @c")
    assert "@a" not in out and "@b" not in out and "@c" not in out


def test_a_team_mention_is_neutralised():
    """@org/team notifies a whole team, which is worse, not better."""
    out = escape_for_github("ask @acme/security")
    assert "@acme/security" not in out


def test_an_email_address_is_left_alone():
    """The `@` in an email is not a mention, and mangling it would corrupt
    a real finding: PII scanning already flags these, and a finding about
    a hardcoded address has to still name it."""
    out = escape_for_github("hardcoded address ops@example.com")
    assert "ops@example.com" in out


def test_a_decorator_is_left_alone():
    """Python findings quote decorators constantly. `@property` is not a
    GitHub username and must survive verbatim, or every message about one
    reads as mangled."""
    assert "@property" in escape_for_github("missing @property here")
    assert "@staticmethod" in escape_for_github("@staticmethod would fit")


# --- issue references --------------------------------------------------


def test_an_issue_reference_does_not_cross_link():
    out = escape_for_github("regression from #1234")
    assert "#1234" not in out
    assert "1234" in out


def test_a_fragment_or_colour_is_left_alone():
    """#fff and #section are not issue references; GitHub only autolinks
    #<digits>."""
    assert "#fff" in escape_for_github("colour #fff")
    assert "#section" in escape_for_github("see #section")


# --- raw HTML ---------------------------------------------------------


def test_raw_html_cannot_forge_structure():
    """GitHub allows <details> and headings in comments, so a message can
    fake CodeGuard's own verdict inside CodeGuard's own comment."""
    out = escape_for_github("</details><h1>CodeGuard: no issues found</h1>")
    assert "<h1>" not in out
    assert "</details>" not in out


def test_escaping_html_is_lossless_for_ordinary_text():
    """The reason this is cheap: `&lt;` renders as `<` in Markdown, so a
    message about `a < b` reads correctly after escaping."""
    out = escape_for_github("index must satisfy a < b && c > d")
    assert out == "index must satisfy a &lt; b &amp;&amp; c &gt; d"


# --- bounds -----------------------------------------------------------


def test_a_long_message_is_capped():
    out = escape_one_line("x" * 10_000)
    assert len(out) <= MAX_ONE_LINE_CHARS + 1  # +1 for the ellipsis


def test_the_cap_cannot_split_an_entity():
    """Truncating after escaping can cut `&amp;` in half, leaving `&am` --
    which renders as literal text, not as `&`. Cosmetic, but it is the
    kind of thing that looks like corruption in a report."""
    out = escape_one_line("&" * MAX_ONE_LINE_CHARS)
    assert "&am" not in out.replace("&amp;", "")


def test_one_line_flattens_newlines():
    """The review body's remainder list is one finding per line, and a
    message containing a newline would break the list -- and could forge a
    heading on the line it creates."""
    out = escape_one_line("first\n# CodeGuard: clean\nsecond")
    assert "\n" not in out


def test_one_line_neutralises_pipes():
    """A raw pipe silently splits a Markdown table row into extra cells."""
    assert "|" not in escape_one_line("a | b")


def test_multi_line_form_keeps_its_newlines():
    """An inline comment body is not a table cell. A tool message with
    real structure should keep it -- only the parts that ACT are removed."""
    out = escape_for_github("line one\nline two")
    assert out.count("\n") == 1


# --- the precision guard ----------------------------------------------


def test_an_ordinary_finding_message_is_unchanged():
    """Every neutralisation over-reaches somewhere. This is the assertion
    that keeps the common case honest."""
    plain = "Possible SQL injection vector through string-based query construction."
    assert escape_for_github(plain) == plain
    assert escape_one_line(plain) == plain


def test_none_and_empty_are_safe():
    assert escape_for_github("") == ""
    assert escape_one_line("") == ""
    assert escape_for_github(None) == ""


def test_a_mention_after_a_dot_is_still_a_mention():
    """The lookbehind was `(?<![\w@.-])`, which skipped an @ after a dot.
    A Semgrep rule id like `rules.@torvalds.sqli` is interpolated into the
    review body, and rule ids come from a rules file a repository supplies.
    An email's local part cannot end in a dot, so the wider lookbehind was
    protecting nothing."""
    assert "@torvalds" not in escape_for_github("rules.@torvalds.sqli")
    assert "@torvalds" not in escape_for_github("see-@torvalds")
    assert "@torvalds" not in escape_for_github("(@torvalds)")
    # Still protected, which is the only thing the lookbehind is for.
    assert "ops@example.com" in escape_for_github("ops@example.com")
    assert "ops.team@example.com" in escape_for_github("ops.team@example.com")
