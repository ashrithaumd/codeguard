"""Eval fixture: a blocking messages.create() call with no timeout,
made directly inside an async handler with no await/to_thread — two
real weaknesses on this one call (missing timeout, and the sync call
itself blocking the event loop).
"""

import anthropic

client = anthropic.Anthropic()


async def handle_request(request):
    resp = client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": "static prompt"}], max_tokens=200, system="Answer concisely.")
    return resp
