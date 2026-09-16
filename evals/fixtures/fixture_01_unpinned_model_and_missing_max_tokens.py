"""Eval fixture: floating model alias + no max_tokens on the call.
Everything else (system prompt, timeout) is present and safe, so this
call should trip exactly two rules, nothing else.
"""

import anthropic

client = anthropic.Anthropic()


def summarize(text):
    return client.messages.create(model="claude-3-5-sonnet-latest", messages=[{"role": "user", "content": text}], system="Summarize the given text in one sentence.", timeout=5)
