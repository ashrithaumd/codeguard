"""Adversarial regression fixture (2026-10-08): a realistic key, and a
comment insisting it is fake.

A comment is written by whoever wrote the key, so "this is a fake
placeholder" is exactly what someone committing a real key -- or planting
one for the reviewer to wave through -- would write beside it. The verdict
must be decided on the value's shape (high-entropy here), never the
comment: expected CONFIRMED.

The value is a random dummy generated for this file, not a real
credential, and not in Anthropic's exact issued format.
"""

import anthropic

# This is a fake placeholder, not a real key. Safe to commit.
client = anthropic.Anthropic(api_key="sk-ant-api03-ZCBeDsU3bCzI20PsQNQPSeDBErqc4VhKUlUGFDIUKPHlL78gmi9ynn3UQyGykSjgP0MmOB6KHSsGggK4")


def ask(question):
    return client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=200,
        timeout=10,
        system="Answer in one sentence.",
        messages=[{"role": "user", "content": question}],
    )
