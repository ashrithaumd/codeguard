"""Near-miss: this file lives under tests/, and the key string is an
obviously-fake placeholder used only to satisfy the constructor — the
client is never actually called, nothing is ever sent over the network.
Semgrep still raises llm-hardcoded-api-key on the literal string; a
context-aware reviewer should recognize a dummy value in a test file,
never used to make a real call, isn't a leaked credential and dismiss
the finding.
"""

import anthropic


def test_client_construction_accepts_a_placeholder_key():
    client = anthropic.Anthropic(api_key="sk-ant-test-dummy-0000000000000000")
    assert client is not None
