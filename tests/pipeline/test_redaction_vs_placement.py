"""Redaction must not break line placement or leak the mask into a fix.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
Step 7 made call_agent redact the content it sends, so the model now sees
`API_KEY = "[redacted]"` where the file says
`API_KEY = "sk-live-..."`.

But placement works by the model ECHOING the line it means and the
pipeline matching that echo against the file:

    nodes.py:832  prompt built from hunk_content   -> call_agent redacts it
    nodes.py:786  _verified_line matches the echo against hunk_content
                  -- THE ORIGINAL, UNREDACTED TEXT

and fixes do the same thing:

    nodes.py:955   prompt built from state["content"]  -> redacted
    nodes.py:1168  file_lines = state["content"]       -- original
    nodes.py:1206  _matched_replacement_range(original, file_lines, ...)

So on a line containing a secret the model echoes the MASKED text, the
match fails, and:

  * a generative finding is demoted to the summary body (line 0) instead
    of being placed inline -- and that is precisely the hardcoded-key
    finding, the one that matters most
  * a fix suggestion is dropped as original_mismatch

Both sides must use the SAME view. Placement matches against the redacted
text the model actually saw. Fixes additionally REFUSE any suggestion whose
replacement contains the mask: a replacement written from text we
deliberately hid is not trustworthy, and committing `[redacted]` into
someone's file would be actively harmful.
"""

from __future__ import annotations

from codeguard.pipeline.nodes import _parse_direct_findings, _verified_line
from codeguard.redact import MASK, redact_source
from codeguard.severity import Severity

SECRET = "sk-live-" + "7b2e" * 8

# Line 2 holds the secret. Line numbers are 1-based and hunk_start is 1.
SOURCE = (
    "import os\n"
    f'API_KEY = "{SECRET}"\n'
    "def call():\n"
    "    return API_KEY\n"
)
REDACTED = redact_source(SOURCE)
SECRET_LINE = 2


def _echo_of(line_no: int, text: str) -> str:
    """What the model would quote back: the line as IT saw it."""
    return text.splitlines()[line_no - 1]


# --- placement ----------------------------------------------------------


def test_the_masked_echo_matches_the_redacted_view():
    """The model echoes what it saw, so the arbiter must be what it saw."""
    line = _verified_line(
        claimed_line=SECRET_LINE,
        echo=_echo_of(SECRET_LINE, REDACTED),
        hunk_lines=REDACTED.splitlines(),
        hunk_start=1, hunk_end=4, agent="quality", path="app.py",
    )
    assert line == SECRET_LINE


def test_the_masked_echo_does_not_match_the_original_view():
    """Pins WHY this matters rather than trusting the comment.

    This is the old behaviour: matching a masked echo against unredacted
    text finds nothing, so the finding is demoted to the summary body.
    """
    line = _verified_line(
        claimed_line=SECRET_LINE,
        echo=_echo_of(SECRET_LINE, REDACTED),
        hunk_lines=SOURCE.splitlines(),          # the original
        hunk_start=1, hunk_end=4, agent="quality", path="app.py",
    )
    assert line == 0, "a masked echo cannot match unredacted text"


def test_a_generative_finding_on_a_secret_line_is_placed_inline():
    """End to end through the parser the generative agents use.

    hunk_content is what _parse_direct_findings matches against. Handed the
    view the model saw, a finding on the secret-bearing line keeps its line
    number instead of collapsing to 0.
    """
    items = [{
        "line": SECRET_LINE,
        "code": _echo_of(SECRET_LINE, REDACTED),
        "severity": "MEDIUM",
        "message": "hardcoded credential should come from the environment",
        "rule_id": "quality.security",
    }]

    findings = _parse_direct_findings(
        items, "app.py", "quality", 1, 4, REDACTED,
        Severity.HIGH, 10,
    )

    assert len(findings) == 1
    assert findings[0].start_line == SECRET_LINE, (
        "the finding on the hardcoded key must be placed inline, not demoted"
    )


def test_an_ordinary_line_is_unaffected():
    """Redaction of one line must not disturb placement on the others."""
    line = _verified_line(
        claimed_line=3,
        echo=_echo_of(3, REDACTED),
        hunk_lines=REDACTED.splitlines(),
        hunk_start=1, hunk_end=4, agent="quality", path="app.py",
    )
    assert line == 3
    assert _echo_of(3, REDACTED) == "def call():", "line 3 is untouched by redaction"


def test_redaction_keeps_the_line_numbering_aligned():
    """The premise everything above rests on: the redacted view has the
    same lines in the same positions, so a line number means the same thing
    in both views."""
    assert len(REDACTED.splitlines()) == len(SOURCE.splitlines())
    for i, (a, b) in enumerate(zip(SOURCE.splitlines(), REDACTED.splitlines()), 1):
        if i != SECRET_LINE:
            assert a == b, f"line {i} changed: {a!r} -> {b!r}"
    assert SECRET not in REDACTED
    assert MASK in REDACTED.splitlines()[SECRET_LINE - 1]


# --- fixes --------------------------------------------------------------


def test_a_replacement_containing_the_mask_is_refused():
    """The mask must never be committable into someone's file.

    A replacement written from text we deliberately hid is not trustworthy
    -- the model could not see the value it was replacing -- and
    `API_KEY = "[redacted]"` committed into a repository is worse than no
    suggestion at all.
    """
    from codeguard.pipeline.nodes import _replacement_is_safe

    assert not _replacement_is_safe(f'API_KEY = "{MASK}"')
    assert not _replacement_is_safe(f'x = 1\nAPI_KEY = "{MASK}"\ny = 2')


def test_an_ordinary_replacement_is_allowed():
    from codeguard.pipeline.nodes import _replacement_is_safe

    assert _replacement_is_safe('API_KEY = os.environ["API_KEY"]')
    assert _replacement_is_safe("cursor.execute(q, (email,))")


# --- fixes, end to end through propose_fix ------------------------------


def _propose(items, content):
    """propose_fix with the fix agent's response stubbed out."""
    import json
    from unittest.mock import patch

    from codeguard.pipeline.llm_call import AgentCallResult
    from codeguard.pipeline.nodes import propose_fix

    result = AgentCallResult(
        raw_text=json.dumps(items), tokens_in=20, tokens_out=10,
        estimated_cost_usd=0.002, latency_s=0.02,
    )
    with patch("codeguard.pipeline.nodes.call_agent", return_value=result):
        return propose_fix({
            "owner": "o", "repo": "r", "path": "app.py",
            "content": content, "findings": [_secret_finding()],
        })


def _secret_finding():
    from codeguard.tools.models import Finding

    return Finding.create(
        file="app.py", start_line=SECRET_LINE, end_line=SECRET_LINE,
        severity=Severity.HIGH, source_tool="bandit", rule_id="B105",
        message="hardcoded credential",
    )


def test_a_fix_on_the_secret_line_is_placed_on_that_line():
    """The whole point: the agent echoes the masked line it was shown, that
    echo matches, and the suggestion anchors to the right line instead of
    being dropped as original_mismatch."""
    finding = _secret_finding()
    out = _propose([{
        "fingerprint": finding.fingerprint,
        "original": _echo_of(SECRET_LINE, REDACTED),
        "replacement": 'API_KEY = os.environ["API_KEY"]',
    }], SOURCE)

    assert len(out["fix_suggestions"]) == 1
    suggestion = out["fix_suggestions"][0]
    assert suggestion.target_line == SECRET_LINE
    assert suggestion.target_end_line == SECRET_LINE


def test_no_posted_suggestion_contains_the_mask():
    """Neither side of what gets posted or stored may carry the mask."""
    finding = _secret_finding()
    out = _propose([{
        "fingerprint": finding.fingerprint,
        "original": _echo_of(SECRET_LINE, REDACTED),
        "replacement": 'API_KEY = os.environ["API_KEY"]',
    }], SOURCE)

    body = out["fix_suggestions"][0].suggestion_body
    assert MASK not in body, "the mask must never reach a suggestion block"
    assert SECRET not in body


def test_a_mask_bearing_replacement_never_becomes_a_suggestion():
    """The refusal, driven through propose_fix rather than the helper: if the
    agent writes the mask back out, nothing is posted at all."""
    finding = _secret_finding()
    out = _propose([{
        "fingerprint": finding.fingerprint,
        "original": _echo_of(SECRET_LINE, REDACTED),
        "replacement": f'API_KEY = "{MASK}"',
    }], SOURCE)

    assert out["fix_suggestions"] == [], (
        "committing the mask would destroy the real value"
    )


def test_the_secret_is_absent_from_the_stored_before_text():
    finding = _secret_finding()
    out = _propose([{
        "fingerprint": finding.fingerprint,
        "original": _echo_of(SECRET_LINE, REDACTED),
        "replacement": 'API_KEY = os.environ["API_KEY"]',
    }], SOURCE)

    assert SECRET not in out["fix_suggestions"][0].original_text
