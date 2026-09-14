"""compute_cache_keys is what worker/main.py calls to prefetch exactly
the (path, content_hash, agent) keys the graph's route_to_* functions
will independently decide to dispatch — this locks the two in step.
"""

from __future__ import annotations

from codeguard.diff.parse import hash_content
from codeguard.pipeline.nodes import compute_cache_keys
from tests.pipeline.conftest import make_finding


def test_compute_cache_keys_includes_security_only_for_files_with_bandit_findings():
    files = {"a.py": "x\n", "b.py": "y\n"}
    findings = [make_finding(file="a.py", tool="bandit")]

    keys = compute_cache_keys(files, {}, findings, ai_aware_enabled=True)

    agents_for_a = {agent for path, _, agent in keys if path == "a.py"}
    agents_for_b = {agent for path, _, agent in keys if path == "b.py"}
    assert "security" in agents_for_a
    assert "security" not in agents_for_b


def test_compute_cache_keys_includes_ai_aware_only_for_ai_touching_files_when_enabled():
    files = {"assistant.py": "import anthropic\n", "plain.py": "x = 1\n"}

    keys = compute_cache_keys(files, {}, [], ai_aware_enabled=True)
    agents_for_assistant = {agent for path, _, agent in keys if path == "assistant.py"}
    agents_for_plain = {agent for path, _, agent in keys if path == "plain.py"}

    assert "ai_aware" in agents_for_assistant
    assert "ai_aware" not in agents_for_plain


def test_compute_cache_keys_excludes_ai_aware_when_disabled():
    files = {"assistant.py": "import anthropic\n"}

    keys = compute_cache_keys(files, {}, [], ai_aware_enabled=False)

    assert not any(agent == "ai_aware" for _, _, agent in keys)


def test_compute_cache_keys_uses_the_same_hash_function_as_the_agents_do():
    content = "import anthropic\n"
    files = {"assistant.py": content}
    findings = [make_finding(file="assistant.py", tool="bandit")]

    keys = compute_cache_keys(files, {}, findings, ai_aware_enabled=True)

    security_hashes = {h for path, h, agent in keys if agent == "security"}
    assert security_hashes == {hash_content(content)}
