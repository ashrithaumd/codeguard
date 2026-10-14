"""The Python pipeline is not changed by multi-language support.

Every Python agent's system prompt is pinned by fingerprint, as are the
cache-key names: a changed prompt changes what a review says, and a changed
cache key re-bills every unchanged file once. New languages get their own
agent (security_generic) and their own key; nothing here may move. If one of
these fails, the change needs the user's sign-off first -- it is not a test
to update in passing.
"""

from __future__ import annotations

import hashlib

import pytest

from codeguard.pipeline import nodes

PINNED = {
    "_SECURITY_SYSTEM_PROMPT": "0d331c51e6e5695f",
    "_AI_AWARE_SYSTEM_PROMPT": "1c9bd12a4689bc0b",
    "_QUALITY_SYSTEM_PROMPT": "50b094323c9f4a97",
    "_TEST_SYSTEM_PROMPT": "37273e27454cfe29",
    "_FIX_SYSTEM_PROMPT": "f7f5e9ccf33ea1eb",
    "_SUMMARY_SYSTEM_PROMPT": "37c2ff025970bf3f",
}


@pytest.mark.parametrize("name, fingerprint", sorted(PINNED.items()))
def test_python_agent_prompts_are_unchanged(name, fingerprint):
    assert hashlib.sha256(getattr(nodes, name).encode()).hexdigest()[:16] == fingerprint


def test_python_cache_keys_are_unchanged():
    assert [nodes.verdict_cache_agent("security"), nodes.verdict_cache_agent("ai_aware"),
            nodes.generative_cache_agent("quality"), nodes.generative_cache_agent("test")] == [
        "security/v2", "ai_aware/v2", "quality/v2", "test/v2"]
