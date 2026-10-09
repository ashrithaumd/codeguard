"""Eval fixture: hardcoded API key on client construction + no system
prompt on the call.

The key was `sk-ant-api03-EXAMPLE1234567890abcdefgh` until 2026-10-08. Under
the shape rule that value is placeholder-shaped ("EXAMPLE", a sequential
run), so dismissing it became the RIGHT answer while ground truth still
said confirmed. It is now a random high-entropy dummy (not a real key,
and not in the issued format), which keeps what this fixture is for; the
EXAMPLE value lives on as near_miss_07, expected dismissed. model/max_tokens/timeout are all present and safe.
"""

import anthropic

client = anthropic.Anthropic(api_key="sk-ant-api03-lFRa24EDTxRw6m7Lr60ePQYFpB0djFfYQS9fIUU0y50IRE6xkGtvT7K71K5ywUXs4pKnS3wMMDDwyRWv")


def classify(text):
    return client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": text}], max_tokens=200, timeout=5)
