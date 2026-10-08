"""Regression fixture (2026-10-08): the negative case for the taint rule.

The prompt is built into a variable and passed the same way as
regress_01 -- but from constants only, and the conversation is extended by
LIST concatenation, which is not prompt splicing. Semgrep should report
nothing here, so there is nothing for the agent to judge: expected no
findings at all.
"""

import anthropic

client = anthropic.Anthropic()

PREFIX = "Classify the following support ticket:\n"


def classify_canned():
    prompt = "Classify the following support ticket:\n" + "The printer is on fire."
    return client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=200,
        timeout=10,
        system="You classify support tickets into billing, bug or other.",
        messages=[{"role": "user", "content": prompt}],
    )


def continue_conversation(history, question):
    messages = history + [{"role": "user", "content": question}]
    return client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=200,
        timeout=10,
        system="You classify support tickets into billing, bug or other.",
        messages=messages,
    )
