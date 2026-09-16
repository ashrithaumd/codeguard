import asyncio
import os
import subprocess

import anthropic

client = anthropic.Anthropic()
cursor = None
user_input = "x"
SYSTEM = "You are a helpful assistant."


# --- llm-prompt-injection-concatenation ---------------------------------

# ruleid: llm-prompt-injection-concatenation
client.messages.create(model="x", messages=[{"role": "user", "content": "prefix" + user_input}], max_tokens=100, system=SYSTEM, timeout=5)

# ruleid: llm-prompt-injection-concatenation
client.messages.create(model="x", messages=[{"role": "user", "content": f"Question: {user_input}"}], max_tokens=100, system=SYSTEM, timeout=5)

# ok: llm-prompt-injection-concatenation
client.messages.create(model="x", messages=[{"role": "user", "content": "static text only"}], max_tokens=100, system=SYSTEM, timeout=5)


# --- llm-missing-system-user-separation ---------------------------------
# (max_tokens/timeout included in both cases so this block doesn't also
# trip llm-call-missing-max-tokens/timeout — each block isolates the one
# thing it tests)

# ruleid: llm-missing-system-user-separation
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, timeout=5)

# ok: llm-missing-system-user-separation
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)


# --- llm-output-to-dangerous-sink (taint) -------------------------------
# Annotation sits directly above the SINK line, not the source line —
# taint-mode matches are reported where the tainted value is used.

resp_a = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ruleid: llm-output-to-dangerous-sink
eval(resp_a.content[0].text)

resp_b = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ruleid: llm-output-to-dangerous-sink
subprocess.run(resp_b.content[0].text)

resp_c = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ok: llm-output-to-dangerous-sink
safe_text = resp_c.content[0].text


# --- llm-output-to-sql (taint) ------------------------------------------

resp_d = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ruleid: llm-output-to-sql
cursor.execute(resp_d.content[0].text)

resp_e = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ok: llm-output-to-sql
cursor.execute("SELECT 1")


# --- llm-call-missing-max-tokens -----------------------------------------
# (system/timeout included in both cases so this block doesn't also trip
# llm-missing-system-user-separation / llm-call-missing-timeout)

# ruleid: llm-call-missing-max-tokens
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], system=SYSTEM, timeout=5)

# ok: llm-call-missing-max-tokens
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)


# --- llm-call-missing-timeout ---------------------------------------------
# (max_tokens/system included in both cases so this block doesn't also
# trip llm-call-missing-max-tokens / llm-missing-system-user-separation)

# ruleid: llm-call-missing-timeout
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM)

# ok: llm-call-missing-timeout
client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)


# --- llm-sync-call-in-async-handler ----------------------------------------
# The pattern matches the whole `async def` block, so semgrep reports the
# match at the function's own def line, not the inner call line —
# annotations go above `async def`, not above the call.

# ruleid: llm-sync-call-in-async-handler
async def handler_bad(request):
    resp = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)
    return resp


# ok: llm-sync-call-in-async-handler
async def handler_ok_awaited(request):
    async_client = anthropic.AsyncAnthropic()
    resp = await async_client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)
    return resp


# ok: llm-sync-call-in-async-handler
async def handler_ok_to_thread(request):
    resp = await asyncio.to_thread(client.messages.create, model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=100, system=SYSTEM, timeout=5)
    return resp


# --- llm-unpinned-model-alias ---------------------------------------------

# ruleid: llm-unpinned-model-alias
model = "claude-3-5-sonnet-latest"

# ok: llm-unpinned-model-alias
model = "claude-3-5-sonnet-20241022"


# --- llm-hardcoded-api-key -------------------------------------------------

# ruleid: llm-hardcoded-api-key
client_bad = anthropic.Anthropic(api_key="sk-ant-api03-abcdefghijklmnopqrstuvwxyz")

# ok: llm-hardcoded-api-key
client_good = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


# --- llm-logging-full-prompt-or-response ------------------------------------

resp_f = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ruleid: llm-logging-full-prompt-or-response
print(resp_f.content[0].text)

resp_g = client.messages.create(model="x", messages=[{"role": "user", "content": "hi"}], max_tokens=10, system=SYSTEM, timeout=5)
# ok: llm-logging-full-prompt-or-response
print(len(resp_g.content[0].text))
