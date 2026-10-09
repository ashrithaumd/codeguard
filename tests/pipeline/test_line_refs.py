"""The model's prose does not state line numbers; the location is shown
separately, and a model's own line number can be wrong.

Live on codeguard-playground the injection finding's What said "Line 43
concatenates user_input..." where the prompt is built on line 44: the
recorded location (44 -> 49) was right and the prose disagreed with it.
Two layers:

  * every agent is told not to (the prompts below);
  * strip_line_refs removes what gets through, wherever model text is
    shown -- the audit page, the review page, PR inline comments and the
    PR summary.

Our own flow note ("Assigned at line 44, sent to the model at line 49.")
is deterministic, correct and not the model's, so it is kept verbatim.
"""

from __future__ import annotations

import pytest

from codeguard.line_refs import strip_line_refs

FLOW = "Assigned at line 44, sent to the model at line 49."


@pytest.mark.parametrize("text, expected", [
    ("Line 43 concatenates user_input directly into the prompt string with no delimiting structure. " + FLOW,
     "This line concatenates user_input directly into the prompt string with no delimiting structure. " + FLOW),
    ("Email parameter is interpolated on line 13 using % formatting.",
     "Email parameter is interpolated using % formatting."),
    ("Used only for delays (line 98: random.uniform for duration) and failures (line 103: random.random).",
     "Used only for delays (random.uniform for duration) and failures (random.random)."),
    ("Hardcoded keys (lines 21, 24, 25 and 45) are placeholders.", "Hardcoded keys are placeholders."),
    ("Lines 21-25 hardcode keys.", "These lines hardcode keys."),
    ("Called at lines 3, 7 and 9 without a timeout.", "Called without a timeout."),
    ("The call in line 33, which has no timeout, blocks.", "The call, which has no timeout, blocks."),
    ("Line 12's query is built with an f-string.", "This line's query is built with an f-string."),
    ("It returns early. Line 9 then reads it.", "It returns early. This line then reads it."),
])
def test_line_numbers_are_removed_and_the_sentence_still_reads(text, expected):
    assert strip_line_refs(text) == expected


@pytest.mark.parametrize("text", [
    "A 3-line function with no docstring.",
    "The deadline 30s is hardcoded.",
    "The pipeline 2 stage retries forever.",
    "Use a single online check.",
    "No line numbers here at all.",
    FLOW,
    "",
])
def test_text_without_a_line_reference_is_untouched(text):
    assert strip_line_refs(text) == text


def test_none_passes_through():
    assert strip_line_refs(None) is None


def test_the_flow_note_survives_alongside_a_stripped_reference():
    text = "Line 43 builds the prompt. " + FLOW
    assert strip_line_refs(text).endswith(FLOW)


# --------------------------------------------------------------------------
# The agents are told
# --------------------------------------------------------------------------

def test_every_prompt_that_writes_prose_forbids_line_numbers():
    from codeguard.pipeline import nodes
    for name in ("_SECURITY_SYSTEM_PROMPT", "_AI_AWARE_SYSTEM_PROMPT", "_QUALITY_SYSTEM_PROMPT", "_TEST_SYSTEM_PROMPT"):
        assert nodes.NO_LINE_NUMBERS_RULE in getattr(nodes, name), name


# --------------------------------------------------------------------------
# Applied where model text is shown
# --------------------------------------------------------------------------

def test_a_pr_inline_comment_has_no_model_line_number():
    from codeguard.severity import Severity
    from codeguard.tools.models import Finding
    from codeguard.worker.main import _findings_to_review_comments

    f = Finding.create(file="db.py", start_line=13, end_line=13, severity=Severity.HIGH, source_tool="bandit",
                       rule_id="B608", message="Email is interpolated on line 13 using % formatting.")
    [comment] = _findings_to_review_comments([f], [])
    assert "line 13" not in comment["body"] and "Email is interpolated using % formatting." in comment["body"]


def test_the_dashboard_has_the_filter():
    from codeguard.api.routes.dashboard import templates
    assert templates.env.filters["no_line_refs"]("Line 4 is bad.") == "This line is bad."
