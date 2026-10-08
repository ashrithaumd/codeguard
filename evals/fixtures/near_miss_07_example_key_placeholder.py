"""Near-miss: a hardcoded key whose VALUE is an obvious placeholder.

`sk-ant-api03-EXAMPLE1234567890abcdefgh` was fixture_02's key until
2026-10-08. Under the shape rule it is placeholder-like on its own --
"EXAMPLE", and a sequential run (1234567890, abcdefgh) -- so dismissing it
is the right answer, and the stated reason must be that shape. There is
deliberately no comment here calling it fake: the shape has to carry the
verdict alone. fixture_02 now holds a random high-entropy dummy and is
expected confirmed; the two together pin both halves of the rule.

Everything else about the call is correct (system prompt, pinned model,
max_tokens, timeout), so the only finding is the one under test.
"""

import anthropic

client = anthropic.Anthropic(api_key="sk-ant-api03-EXAMPLE1234567890abcdefgh")


def classify(text):
    return client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=200,
        timeout=5,
        system="Classify the text as billing, bug or other.",
        messages=[{"role": "user", "content": text}],
    )
