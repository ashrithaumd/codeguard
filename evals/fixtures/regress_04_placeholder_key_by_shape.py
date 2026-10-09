"""Regression fixture (2026-10-08): an obvious placeholder, with NO comment
saying so.

The other half of the shape rule. The value is placeholder-shaped on its
own ("your-api-key-here"), so a dismissal is allowed, and its stated
reason has to be the shape -- there is no comment here to lean on.
Expected DISMISSED.
"""

import anthropic

client = anthropic.Anthropic(api_key="your-api-key-here")


def ask(question):
    return client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=200,
        timeout=10,
        system="Answer in one sentence.",
        messages=[{"role": "user", "content": question}],
    )
