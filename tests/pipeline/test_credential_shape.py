"""A credential verdict is decided by the value's SHAPE, never by a comment.

THE BUG. Upstream redaction means the verdict agents see `[redacted]`
where the file holds a key. On codeguard-playground the AI-aware agent
dismissed all four llm-hardcoded-api-key hits, and its stated reason was
two things at once: the value was "the literal placeholder string
'[redacted]'", and a docstring said the keys were "obviously fake".

Neither is evidence. The mask is ours, so it says nothing about the value
behind it; and a comment is written by whoever wrote the key, which makes
"this is a fake placeholder" exactly the sentence an attacker would plant
next to a real one.

THE FIX, in two halves:

  1. The prompt carries a non-secret description of the value in place of
     the bare mask -- `[redacted: 51-char sk-ant-style token, high-entropy]`
     -- so the agent can tell `...000000000000` from a real key without
     ever seeing either.
  2. A deterministic guard: a dismissal of a credential rule is honoured
     only when every occurrence's value is placeholder-shaped. A
     high-entropy value falls back to the confirmed raw finding, whatever
     the model said and whatever the file's comments claim -- the same
     fallback dismissals_enabled=False already applies to every rule.

Stored and logged text is untouched: redact() and the default
redact_source() still produce the plain `[redacted]`.
"""

from __future__ import annotations

import json
import secrets
import string
from unittest.mock import patch

import pytest

from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.pipeline.nodes import review_ai_aware, review_security
from codeguard.redact import MASK, classify_secret, redact, redact_source
from tests.pipeline.conftest import make_finding

_ALNUM = string.ascii_letters + string.digits


def _random_body(n: int) -> str:
    """A random dummy, generated per run. Never a real key, and never
    committed: nothing here is a literal that could be one."""
    return "".join(secrets.choice(_ALNUM) for _ in range(n))


def _realistic_anthropic_dummy() -> str:
    return "sk-ant-api03-" + _random_body(80)


# --------------------------------------------------------------------------
# classify_secret
# --------------------------------------------------------------------------

def test_a_random_key_shaped_value_is_high_entropy():
    key = _realistic_anthropic_dummy()
    shape = classify_secret(key)
    assert shape.family == "sk-ant"
    assert shape.kind == "high-entropy"
    assert shape.length == len(key)


@pytest.mark.parametrize("value", [
    "sk-placeholder-not-a-real-key-000000000000",
    "placeholder-not-a-real-key-2222222222222222",
    "your-api-key-here",
    "<API_KEY>",
    "x" * 32,
    "sk-ant-test-dummy-0000000000000000",
    "sk-ant-api03-EXAMPLE1234567890abcdefgh",
    "changeme",
])
def test_obvious_placeholders_are_placeholder_like(value):
    assert classify_secret(value).kind == "placeholder-like"


def test_a_vendor_test_mode_prefix_is_not_mistaken_for_a_placeholder():
    """`sk_test_` is a real (test-mode) Stripe credential. The marker
    words are checked against the body AFTER the vendor prefix."""
    assert classify_secret("sk_test_" + _random_body(32)).kind == "high-entropy"


def test_the_hint_never_contains_any_part_of_the_value():
    key = _realistic_anthropic_dummy()
    body = key[len("sk-ant-api03-"):]
    hint = classify_secret(key).hint()
    assert hint.startswith("[redacted: ") and hint.endswith("]")
    for i in range(len(body) - 3):
        assert body[i:i + 4] not in hint


# --------------------------------------------------------------------------
# redact_source(hints=True)
# --------------------------------------------------------------------------

def test_hints_describe_the_value_in_place_of_the_bare_mask():
    key = _realistic_anthropic_dummy()
    src = f'client = anthropic.Anthropic(api_key="{key}")\n'
    out = redact_source(src, hints=True)
    assert key not in out
    assert f"[redacted: {len(key)}-char sk-ant-style token, high-entropy]" in out
    assert out.count("\n") == src.count("\n")


def test_without_hints_redaction_is_exactly_what_it_was():
    """Stored and logged text keeps the plain mask: this change must not
    weaken -- or alter -- redaction anywhere but the verdict prompt."""
    key = _realistic_anthropic_dummy()
    src = f'API_KEY = "{key}"\n'
    assert redact_source(src) == f'API_KEY = "{MASK}"\n'
    assert redact(src) == f'API_KEY = "{MASK}"\n'


def test_redacting_a_hinted_text_again_leaves_the_hint_alone():
    """call_agent redacts every prompt again. The hint has to survive
    that second pass, or the agent sees the bare mask after all."""
    key = _realistic_anthropic_dummy()
    hinted = redact_source(f'ANTHROPIC_API_KEY = "{key}"\n', hints=True)
    assert redact_source(hinted) == hinted
    assert redact(hinted) == hinted


def test_a_value_dressed_up_as_a_hint_is_still_redacted():
    """The hint skip matches the hint FORMAT exactly, so a secret with a
    hint-looking prefix glued on cannot ride through."""
    key = _random_body(40)
    src = f'api_key = "[redacted: 5-char token, placeholder-like]{key}"\n'
    assert key not in redact_source(src)


# --------------------------------------------------------------------------
# The verdict guard
# --------------------------------------------------------------------------

def _result(items) -> AgentCallResult:
    return AgentCallResult(raw_text=json.dumps(items), tokens_in=10, tokens_out=5,
                           estimated_cost_usd=0.001, latency_s=0.01)


def _state(content: str, findings) -> dict:
    return {"owner": "o", "repo": "r", "path": "app.py", "content": content,
            "patch": "", "findings": findings, "hunk_cache_hits": {}}


_DISMISS_AS_FAKE = [{
    "rule_id": "llm-hardcoded-api-key", "verdict": "dismissed",
    "message": "A comment says this is a fake placeholder.",
}]


def test_a_realistic_key_with_a_fake_comment_is_confirmed_even_if_the_model_dismisses():
    key = _realistic_anthropic_dummy()
    content = (
        "import anthropic\n"
        "# this is a fake placeholder, not a real key\n"
        f'client = anthropic.Anthropic(api_key="{key}")\n'
    )
    finding = make_finding(file="app.py", line=3, tool="semgrep", rule_id="llm-hardcoded-api-key")

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(_DISMISS_AS_FAKE)):
        out = review_ai_aware(_state(content, [finding]))

    assert [f.rule_id for f in out["findings"]] == ["llm-hardcoded-api-key"]
    assert out.get("dismissed_findings", []) == []


def test_a_placeholder_key_may_still_be_dismissed():
    content = 'import anthropic\nclient = anthropic.Anthropic(api_key="your-api-key-here")\n'
    finding = make_finding(file="app.py", line=2, tool="semgrep", rule_id="llm-hardcoded-api-key")
    verdict = [{"rule_id": "llm-hardcoded-api-key", "verdict": "dismissed",
                "message": "The value is placeholder-shaped (contains 'your', 'here')."}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(verdict)):
        out = review_ai_aware(_state(content, [finding]))

    assert out["findings"] == []
    assert [d.rule_id for d in out["dismissed_findings"]] == ["llm-hardcoded-api-key"]


def test_one_real_key_among_placeholders_keeps_the_whole_rule_confirmed():
    """One verdict per rule_id: a dismissal covers every occurrence, so it
    is honoured only if EVERY occurrence is placeholder-shaped."""
    key = _realistic_anthropic_dummy()
    content = (
        'a = anthropic.Anthropic(api_key="your-api-key-here")\n'
        f'b = anthropic.Anthropic(api_key="{key}")\n'
    )
    findings = [
        make_finding(file="app.py", line=1, tool="semgrep", rule_id="llm-hardcoded-api-key"),
        make_finding(file="app.py", line=2, tool="semgrep", rule_id="llm-hardcoded-api-key"),
    ]
    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(_DISMISS_AS_FAKE)):
        out = review_ai_aware(_state(content, findings))

    assert sorted(f.start_line for f in out["findings"]) == [1, 2]


def test_bandit_hardcoded_password_rules_get_the_same_guard():
    secret = _random_body(40)
    content = f'DB_PASSWORD = "{secret}"  # fake, for local use only\n'
    finding = make_finding(file="app.py", line=1, tool="bandit", rule_id="B105")
    verdict = [{"rule_id": "B105", "verdict": "dismissed", "message": "Comment says fake."}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(verdict)):
        out = review_security(_state(content, [finding]))

    assert [f.rule_id for f in out["findings"]] == ["B105"]


def test_a_non_credential_dismissal_is_untouched():
    content = "eval(x)\n"
    finding = make_finding(file="app.py", line=1, tool="bandit", rule_id="B307")
    verdict = [{"rule_id": "B307", "verdict": "dismissed", "message": "x is a literal tuple above."}]

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(verdict)):
        out = review_security(_state(content, [finding]))

    assert out["findings"] == []


def test_the_verdict_prompt_carries_the_hint_and_never_the_key():
    key = _realistic_anthropic_dummy()
    content = f'client = anthropic.Anthropic(api_key="{key}")\n'
    finding = make_finding(file="app.py", line=1, tool="semgrep", rule_id="llm-hardcoded-api-key")

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result([])) as call:
        review_ai_aware(_state(content, [finding]))

    sent = call.call_args.kwargs["user_content"]
    assert key not in sent
    assert "high-entropy" in sent


def test_the_guard_uses_absolute_lines_inside_an_audit_chunk():
    """Audit mode sends a SLICE of the file with findings still on their
    absolute line numbers; content_first_line maps one onto the other."""
    key = _realistic_anthropic_dummy()
    chunk = f'client = anthropic.Anthropic(api_key="{key}")\n'
    finding = make_finding(file="app.py", line=120, tool="semgrep", rule_id="llm-hardcoded-api-key")
    state = {**_state(chunk, [finding]), "content_first_line": 120}

    with patch("codeguard.pipeline.nodes.call_agent", return_value=_result(_DISMISS_AS_FAKE)):
        out = review_ai_aware(state)

    assert [f.start_line for f in out["findings"]] == [120]


# --------------------------------------------------------------------------
# "key" (and "secret", "token") alone never make a value a placeholder
# --------------------------------------------------------------------------

def test_a_random_token_that_happens_to_contain_key_is_not_a_placeholder():
    """A real key is free to contain the letters k-e-y, delimited or not.
    Only alongside a real placeholder sign -- "placeholder", "example",
    "your", "xxx", "dummy", or a long repeated run -- does it count."""
    for word in ("key", "KEY", "secret", "token"):
        value = "sk-ant-api03-" + _random_body(40) + f"-{word}-" + _random_body(40)
        assert classify_secret(value).kind == "high-entropy", word


@pytest.mark.parametrize("value", [
    "your-key-here", "example-api-key", "xxx-key-xxx", "dummy-secret-key", "sk-key-000000000000",
])
def test_key_with_a_real_placeholder_sign_is_still_a_placeholder(value):
    assert classify_secret(value).kind == "placeholder-like"


@pytest.mark.parametrize("value", [
    # codeguard-playground assistant.py:21, :24, :25, :45 -- the shapes, not
    # copied from the repo: marker words and a long repeated run, as there.
    "sk-placeholder-not-a-real-key-000000000000",
    "sk-placeholder-not-a-real-key-111111111111",
    "placeholder-not-a-real-key-2222222222222222",
    "placeholder-not-a-real-key-3333333333",
])
def test_the_playground_keys_are_still_placeholder_shaped(value):
    assert classify_secret(value).kind == "placeholder-like"
