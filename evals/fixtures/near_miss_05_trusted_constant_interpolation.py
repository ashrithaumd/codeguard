"""Near-miss: an f-string splices a variable into the prompt content,
matching llm-prompt-injection-concatenation's syntactic pattern exactly
— but the variable is a module-level constant the developer controls,
never derived from PR/user input, and no other part of the prompt is
built from anything external either. Semgrep can't distinguish a
constant from untrusted data; a context-aware reviewer, seeing LANGUAGE
defined right above as a literal, should dismiss the finding.
"""

import anthropic

client = anthropic.Anthropic()

LANGUAGE = "English"


def get_iso_code():
    return client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": f"What is the ISO 639-1 code for {LANGUAGE}?"}], max_tokens=200, system="You are a translator.", timeout=5)
