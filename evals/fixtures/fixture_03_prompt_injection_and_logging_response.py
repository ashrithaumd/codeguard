"""Eval fixture: untrusted input spliced into a prompt via f-string +
the full model response text printed to logs. Two separate calls so
each weakness sits on its own line, isolated from the other.
"""

import anthropic

client = anthropic.Anthropic()


def answer(user_question):
    return client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": f"Question: {user_question}"}], max_tokens=200, system="Answer concisely.", timeout=5)


def answer_and_log(user_question):
    resp = client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": "static prompt"}], max_tokens=200, system="Answer concisely.", timeout=5)
    print(resp.content[0].text)
    return resp
