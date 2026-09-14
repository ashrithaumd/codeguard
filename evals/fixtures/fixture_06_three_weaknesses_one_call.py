"""Eval fixture: three separate weaknesses on a single call — a
floating model alias, no max_tokens, and no system prompt. This is the
same shape used for the live PR verification (a new LLM-calling file
with exactly 3 planted weaknesses).
"""

import anthropic

client = anthropic.Anthropic()


def chat(message):
    return client.messages.create(model="claude-3-5-sonnet-latest", messages=[{"role": "user", "content": message}], timeout=5)
