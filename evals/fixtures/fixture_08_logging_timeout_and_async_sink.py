"""Eval fixture: full response text logged via `logging`, plus a
blocking call with no timeout made directly inside an async handler —
three weaknesses (logging, missing timeout, sync-in-async) across two
call sites.
"""

import logging

import anthropic

logger = logging.getLogger(__name__)
client = anthropic.Anthropic()


async def handle_request(request):
    resp = client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": "static prompt"}], max_tokens=200, system="Answer concisely.")
    logger.info("model response: %s", resp.content[0].text)
    return resp
