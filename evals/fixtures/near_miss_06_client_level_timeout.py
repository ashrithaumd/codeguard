"""Near-miss: no timeout= is passed on this specific call, but the
Anthropic client was constructed with a client-level default timeout
that applies to every call made through it — real SDK behavior, not a
gap. Semgrep's rule only looks at the individual .create() call's own
arguments, so it raises llm-call-missing-timeout; a context-aware
reviewer, seeing the client construction right above, should recognize
the timeout is already set for every call and dismiss the finding.
"""

import anthropic

client = anthropic.Anthropic(timeout=10.0)


def ask(question):
    return client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": question}], max_tokens=200, system="Answer concisely.")
