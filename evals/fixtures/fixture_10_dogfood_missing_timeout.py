"""Eval fixture: added in Phase 9.1, modeled directly on a REAL finding
from dogfooding evals/RESULTS.md — DocuMind's backend/llm.py had two
separate messages.create() calls, neither with an explicit timeout,
correctly confirmed by review_ai_aware live against real code (not a
fixture written alongside the rule). This fixture reproduces that same
shape as a permanent regression fixture, since the original finding
lives in a different repo this eval harness doesn't have access to.

Deliberately NOT inside an async handler (unlike fixture_05) and
otherwise complete (model pinned, max_tokens set) — isolates
llm-call-missing-timeout as the only expected confirmed rule_id here.
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
