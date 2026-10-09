"""Regression fixture (2026-10-08): untrusted input concatenated into a
variable, and the variable passed as the prompt.

The exact shape of codeguard-playground assistant.py:44, which
llm-prompt-injection-concatenation matched nothing on while every pattern
required the concatenation INLINE in the content value. The rule is now
taint-mode and follows `prompt` from the splice to the call.

Everything else about the call is deliberately correct (pinned model,
max_tokens, timeout, a system prompt) so the only finding is the one under
test.
"""

import anthropic

client = anthropic.Anthropic()


def classify(user_input):
    prompt = "Classify the following support ticket:\n" + user_input
    return client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=200,
        timeout=10,
        system="You classify support tickets into billing, bug or other.",
        messages=[{"role": "user", "content": prompt}],
    )
