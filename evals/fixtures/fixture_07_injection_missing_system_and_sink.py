"""Eval fixture: prompt-injection concatenation + missing system prompt
on the same call (untrusted input, no system separation to defend
against it) plus a separate call whose response flows into
subprocess.run() — three weaknesses across two calls.
"""

import subprocess

import anthropic

client = anthropic.Anthropic()


def ask(user_input):
    return client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": "prefix: " + user_input}], max_tokens=200, timeout=5)


def run_suggested_command(user_input):
    resp = client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": "static prompt"}], max_tokens=200, system="Suggest a shell command.", timeout=5)
    subprocess.run(resp.content[0].text)
