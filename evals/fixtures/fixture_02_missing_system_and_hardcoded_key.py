"""Eval fixture: hardcoded API key on client construction + no system
prompt on the call. model/max_tokens/timeout are all present and safe.
"""

import anthropic

client = anthropic.Anthropic(api_key="sk-ant-api03-EXAMPLE1234567890abcdefgh")


def classify(text):
    return client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": text}], max_tokens=200, timeout=5)
