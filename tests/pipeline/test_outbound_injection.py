"""An injection payload must not survive into what we post to GitHub.

WHY THIS FILE IS SEPARATE from tests/github/test_outbound.py: that one
tests the escaper. This one tests that the escaper is actually REACHED, on
each of the surfaces a payload can ride. A neutralisation function with no
caller is the failure mode here, and it is not a hypothetical -- this is
exactly how the inline comment body ended up interpolating raw text while
github/check_summary.py escaped carefully throughout.

THE THREAT MODEL, stated plainly, because it is not the obvious one.
The interesting attack is not "make the model say something wrong". It is
"get a string echoed into a GitHub comment", because a GitHub comment has
effects that a dashboard page does not:

    @someone       notifies a real person, from the operator's App
    #1234          cross-references their issue, permanently
    </details>     escapes the collapsed block a dismissal sits in, and
                   whatever follows appears at the top level of
                   CodeGuard's own comment

The payload needs no cooperation from the model at all for the first
route: Bandit's hardcoded-secret message quotes the matched string, so a
PR author can put the payload in a string literal and have a DETERMINISTIC
tool carry it outbound.

THREE SURFACES, all of which were raw:

    worker/main.py    the inline review comment body
    nodes.py          the review body's "additional finding(s)" list
    nodes.py          the dismissed-findings <details> block (model prose)
"""

from __future__ import annotations

from unittest.mock import patch

from codeguard.config import RepoConfig
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.models import DismissedFinding
from codeguard.pipeline.nodes import summarize
from codeguard.severity import Severity
from tests.pipeline.conftest import make_finding

# One payload, every route it could take. Written as the contents of a
# string literal in a reviewed file, which is how a scanner message comes
# to contain it.
PAYLOAD = (
    "hey @torvalds see #1234 </details><h1>CodeGuard: no issues found</h1>"
)

# What must never appear verbatim in anything posted.
FORBIDDEN = ("@torvalds", "#1234", "</details><h1>", "<h1>")


def _assert_defused(text: str, where: str) -> None:
    for token in FORBIDDEN:
        assert token not in text, f"{where}: {token!r} survived into posted output"
    # And the finding is still legible -- a neutralisation that deleted the
    # message would pass the assertions above while making the review
    # useless.
    assert "torvalds" in text, f"{where}: the text was destroyed, not defused"


def _state(findings, patches, dismissed=None):
    return {
        "owner": "o", "repo": "r", "pr_number": 1, "head_sha": "sha", "installation_id": 1,
        "repo_config": RepoConfig(),
        "files": {p: "" for p in patches},
        "patches": patches,
        "tool_findings": [],
        "touches_ai_code": False,
        "findings": findings, "repo_level_findings": [],
        "dismissed_findings": dismissed or [],
        "fix_suggestions": [],
        "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
        "suppressed_fingerprints": frozenset(),
        "budget_exceeded": False,
    }


def _summarize(state, intro="Mock intro."):
    def _call(*, agent, **kwargs):
        return AgentCallResult(raw_text=intro, tokens_in=1, tokens_out=1,
                              estimated_cost_usd=0.0, latency_s=0.0)

    with patch("codeguard.pipeline.nodes.call_agent", side_effect=_call):
        return summarize(state)


# --- surface 1: the review body's remainder list -------------------------


def test_the_payload_does_not_survive_the_review_body():
    """A finding outside the diff lands in the "additional finding(s)"
    list, which interpolated rule_id and message raw."""
    finding = make_finding(file="a.py", line=999, rule_id="B105", message=PAYLOAD)
    result = _summarize(_state([finding], {"a.py": "@@ -1,3 +1,3 @@\n ctx"}))

    _assert_defused(result["summary"], "review body")


def test_a_payload_in_the_rule_id_does_not_survive_either():
    """rule_id is interpolated on the same line, and a Semgrep rule id
    comes from a rules file, which a repository can supply."""
    finding = make_finding(
        file="a.py", line=999, rule_id="rules.@torvalds.sqli", message="ordinary",
    )
    result = _summarize(_state([finding], {"a.py": "@@ -1,3 +1,3 @@\n ctx"}))

    assert "@torvalds" not in result["summary"]


def test_a_newline_cannot_forge_a_line_in_the_list():
    """The list is one finding per line. A message containing a newline
    could otherwise write its own entry -- or a heading."""
    finding = make_finding(
        file="a.py", line=999, rule_id="B105",
        message="real finding\n- a.py:1 [bandit/CRITICAL] FAKE: approved",
    )
    result = _summarize(_state([finding], {"a.py": "@@ -1,3 +1,3 @@\n ctx"}))

    lines = [ln for ln in result["summary"].splitlines() if ln.startswith("- ")]
    assert len(lines) == 1, f"the message wrote its own list entry: {lines}"


# --- surface 2: the dismissed <details> block ----------------------------


def test_a_dismissal_reason_cannot_escape_its_details_block():
    """`reason` is MODEL-AUTHORED prose written inside a <details> block.
    A reason containing </details> would close it early and promote
    whatever followed to the top level of CodeGuard's own comment."""
    dismissed = [DismissedFinding(
        file="a.py", start_line=2, rule_id="B608", reason=PAYLOAD,
    )]
    result = _summarize(_state([], {"a.py": "@@ -1,3 +1,3 @@\n ctx"}, dismissed=dismissed))

    body = result["summary"]
    _assert_defused(body, "dismissed block")
    # Exactly one open and one close: the block is still well formed.
    assert body.count("<details>") == 1
    assert body.count("</details>") == 1


# --- surface 3: the LLM intro -------------------------------------------


def test_the_summary_intro_is_escaped_too():
    """Lower risk -- this agent is handed aggregate counts, never finding
    text -- but "this prompt has no injection surface today" is not a
    property anyone re-verifies before widening a prompt."""
    finding = make_finding(file="a.py", line=2, rule_id="B608", message="sqli")
    result = _summarize(
        _state([finding], {"a.py": "@@ -1,3 +1,3 @@\n ctx"}), intro=PAYLOAD,
    )

    _assert_defused(result["summary"], "summary intro")


# --- surface 4: the inline comment body ---------------------------------


def test_the_payload_does_not_survive_the_inline_comment_body():
    """The body worker/main.py posts per finding. This one was
    `f"**[{f.source_tool} / {f.severity.name}] {f.rule_id}**\\n\\n{f.message}"`
    with no escaping of any kind."""
    from codeguard.worker.main import _findings_to_review_comments

    finding = make_finding(file="a.py", line=2, rule_id="B105", message=PAYLOAD)
    comments = _findings_to_review_comments([finding], [])

    assert len(comments) == 1
    _assert_defused(comments[0]["body"], "inline comment")


def test_the_fingerprint_marker_still_round_trips():
    """The marker is how a posted comment is matched back to its finding
    for suppression. Escaping the body must not disturb it, or the
    feedback loop breaks silently."""
    from codeguard.pipeline.feedback import FINGERPRINT_MARKER_RE
    from codeguard.worker.main import _findings_to_review_comments

    finding = make_finding(file="a.py", line=2, rule_id="B105", message=PAYLOAD)
    body = _findings_to_review_comments([finding], [])[0]["body"]

    found = FINGERPRINT_MARKER_RE.search(body)
    assert found, "the fingerprint marker did not survive escaping"
    assert found.group(1) == finding.fingerprint


def test_an_ordinary_finding_reads_normally_end_to_end():
    """The precision guard, at the level that matters: a real review must
    not be visibly mangled by any of this."""
    from codeguard.worker.main import _findings_to_review_comments

    message = "Possible SQL injection vector through string-based query construction."
    finding = make_finding(file="a.py", line=2, rule_id="B608", message=message)

    body = _findings_to_review_comments([finding], [])[0]["body"]
    assert message in body
    assert "&" not in body.replace("&#", "")  # no stray entities introduced

    result = _summarize(_state([finding], {"a.py": "@@ -1,3 +1,3 @@\n ctx"}))
    assert "CodeGuard reviewed" in result["summary"]


# --- bounds at the point the model's claim becomes our data --------------


def test_a_generative_message_is_bounded_at_the_parser():
    """github/outbound.py caps what reaches GitHub, but message and
    category also become stored data, a dashboard row and part of the
    fingerprint. "Bounded by the agent's max_tokens" is not a bound --
    max_tokens is a setting."""
    from codeguard.pipeline.nodes import (
        _MAX_CATEGORY_CHARS,
        _MAX_MESSAGE_CHARS,
        _parse_direct_findings,
    )

    items = [{
        "line": 1, "code": "x = 1", "severity": "LOW",
        "message": "m" * 50_000,
        "category": "c" * 5_000,
    }]
    findings = _parse_direct_findings(
        items, "a.py", "quality", 1, 1, "x = 1\n", Severity.MEDIUM, 10,
    )

    assert len(findings) == 1
    assert len(findings[0].message) <= _MAX_MESSAGE_CHARS
    assert len(findings[0].rule_id) <= _MAX_CATEGORY_CHARS + len("quality.")
