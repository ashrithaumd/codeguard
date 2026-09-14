"""Near-miss: this call has no `system=` kwarg of its own, but $CLIENT
here is a wrapper class whose .create() always injects the system
prompt internally before delegating to the real SDK — Semgrep's pattern
matches any object with a .messages.create(...) call, it can't tell
$CLIENT isn't a raw anthropic.Anthropic() instance. A context-aware
reviewer reading SystemInjectingClient's own definition, right above
the call, should recognize the separation is actually enforced and
dismiss the finding.
"""

import anthropic


class SystemInjectingClient:
    """Every call through this wrapper gets the same system prompt —
    callers never pass (or need to pass) their own `system=`."""

    def __init__(self):
        self._client = anthropic.Anthropic()

    @property
    def messages(self):
        return self

    def create(self, model, messages, max_tokens, timeout):
        return self._client.messages.create(model=model, messages=messages, max_tokens=max_tokens, system="You are a helpful assistant. Always stay on topic.", timeout=timeout)


client = SystemInjectingClient()


def ask(question):
    return client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": question}], max_tokens=200, timeout=5)
