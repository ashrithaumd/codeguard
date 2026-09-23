"""Eval fixture: added in Phase 9.1, modeled directly on a REAL finding
from dogfooding evals/RESULTS.md — DocuMind's backend/llm.py had two
separate messages.create() calls, neither with an explicit timeout,
correctly confirmed by review_ai_aware live against real code (not a
fixture written alongside the rule). This fixture reproduces that same
shape as a permanent regression fixture, since the original finding
lives in a different repo this eval harness doesn't have access to.

Deliberately NOT inside an async handler (unlike fixture_05), and the
model is pinned with max_tokens set.

CORRECTION (2026-09-23): this docstring used to claim the fixture
"isolates llm-call-missing-timeout as the only expected confirmed
rule_id". It never did — complete_text() below has no system= either, so
llm-missing-system-user-separation has always fired on it, confirmed
against the pre-expansion 10-rule set. The ground truth simply never
listed it, which quietly inflated the AI-aware precision number. Both
rule_ids are now in ground_truth.json.
"""

import anthropic

client = anthropic.Anthropic()


def complete_text(prompt: str) -> str:
    response = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def complete_json(prompt: str) -> dict:
    response = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=500,
        system="Respond with JSON only.",
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text
