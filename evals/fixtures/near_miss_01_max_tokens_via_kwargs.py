"""Near-miss: max_tokens IS set, just not as a literal kwarg in this
call — it comes from a shared, pre-populated kwargs dict spread into
the call with **. Semgrep's syntactic pattern can't see into the dict,
so it raises llm-call-missing-max-tokens; a context-aware reviewer
reading the surrounding code should recognize it's actually set and
dismiss the finding.
"""

import anthropic

client = anthropic.Anthropic()

REQUEST_DEFAULTS = {"max_tokens": 1024, "timeout": 5}


def ask(question):
    return client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": question}], system="Answer concisely.", **REQUEST_DEFAULTS)
