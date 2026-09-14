"""Near-miss: the floating model alias string is real source text, but
it's inside an `if False:` block explicitly commented as unreachable
legacy code — never executed. Semgrep has no reachability analysis, so
it raises llm-unpinned-model-alias on the dead-code line; a
context-aware reviewer should recognize it can't run and dismiss it.
The live call actually used is pinned.
"""

import anthropic

client = anthropic.Anthropic()

if False:  # legacy code path, kept for reference only, never executed
    model = "claude-3-5-sonnet-latest"


def ask(question):
    return client.messages.create(model="claude-sonnet-4-5", messages=[{"role": "user", "content": question}], max_tokens=200, system="Answer concisely.", timeout=5)
