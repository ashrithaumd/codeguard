"""compute_cache_keys is what worker/main.py calls to prefetch exactly
the (path, content_hash, agent) keys the graph's route_to_* functions
will independently decide to dispatch — this locks the two in step.
"""

from __future__ import annotations

from unittest.mock import patch

from codeguard.diff.parse import hash_content
from codeguard.pipeline.models import CachedAgentResult
from codeguard.pipeline.nodes import compute_cache_keys, review_quality, route_to_quality_reviews
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


def test_the_generative_key_compute_cache_keys_prefetches_is_the_one_the_agent_reads():
    """The two sides of the generative cache key, locked together.

    compute_cache_keys prefetches; _run_generative_agent looks up and
    writes. They derive the key independently, so a version bump applied
    to one and not the other would not fail anything loudly — it would
    just turn every quality/test call into a permanent cache miss, and
    the only symptom would be a quietly larger API bill.
    """
    files = {"a.py": "def f(x):\n    return x + 1\n"}
    patches = {"a.py": "@@ -1,2 +1,2 @@\n context"}
    cached = make_finding(file="a.py", tool="quality-agent", message="from cache")

    quality_keys = [k for k in compute_cache_keys(files, patches, [], ai_aware_enabled=False)
                    if k[2].startswith("quality")]
    assert len(quality_keys) == 1, "one hunk, one quality key"
    hits = {quality_keys[0]: CachedAgentResult(findings=[cached])}

    [send] = route_to_quality_reviews({"owner": "o", "repo": "r", "files": files,
                                       "patches": patches, "hunk_cache_hits": hits})

    with patch("codeguard.pipeline.nodes.call_agent") as mock_call:
        result = review_quality(send.arg)

    mock_call.assert_not_called()  # the prefetched key must be the key the agent looks up
    assert result["findings"] == [cached]
