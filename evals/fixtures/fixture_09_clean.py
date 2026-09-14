"""Eval fixture: no planted weaknesses — every field present, pinned
model, no dangerous sinks, no raw logging, key from the environment.
Exists to measure the agent's false-positive rate on clean code, not
just its recall on bad code.
"""

import os

import anthropic

client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])


def summarize(text):
    resp = client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": "static prompt"}], max_tokens=200, system="Summarize the given text.", timeout=5)
    return resp.content[0].text
