"""CodeGuard's own LLM-security rules for JavaScript/TypeScript
(rules_lang/js-llm-security.yaml), end to end through the generic path:
run with the vendored rules under the codeguard-rules name, MEDIUM and up
judged by security_generic, a hardcoded key decided by its shape with its
line masked and never sent. Python's LLM rules and agents are untouched.
"""

from __future__ import annotations

import random
import string
import sys

import pytest

from codeguard.pipeline.generic_review import GENERIC_CREDENTIAL_RULES, content_for_model, triage
from codeguard.severity import Severity
from codeguard.tools.semgrep_runner import OWN_TOOL_NAME, run_vendor_rules

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Semgrep does not run on Windows")

KEY_RULE = "codeguard-js-llm-hardcoded-api-key"


def _key(seed):
    rng = random.Random(seed)
    return "sk-proj-" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(40))


ASSISTANT = """import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ timeout: 30_000 });

export async function classify(ticket: string) {
  const prompt = "Classify the following support ticket:\\n" + ticket;
  return client.messages.create({
    model: "claude-sonnet-4-5",
    max_tokens: 256,
    system: "You classify tickets.",
    messages: [{ role: "user", content: prompt }],
  });
}
"""


def test_injection_through_a_variable_is_found_and_goes_to_the_model():
    findings = run_vendor_rules({"src/assistant.ts": ASSISTANT})
    [f] = [f for f in findings if f.rule_id == "codeguard-js-llm-prompt-injection-concatenation"]
    assert f.source_tool == OWN_TOOL_NAME and f.severity == Severity.HIGH and f.start_line == 11
    t = triage(findings, {"src/assistant.ts": ASSISTANT}, max_files=10, max_findings_per_file=30)
    assert "codeguard-js-llm-prompt-injection-concatenation" in [x.rule_id for x in t.to_model["src/assistant.ts"]]


def test_a_well_built_call_raises_nothing():
    safe = ASSISTANT.replace('"Classify the following support ticket:\\n" + ticket', "ticket")
    assert [f for f in run_vendor_rules({"src/assistant.ts": safe}) if f.rule_id.startswith("codeguard-js-llm-")] == []


def test_a_hardcoded_key_is_decided_by_shape_masked_and_never_sent():
    assert KEY_RULE in GENERIC_CREDENTIAL_RULES
    key = _key(3)
    content = ('import OpenAI from "openai";\n\nconst client = new OpenAI({\n  timeout: 10_000,\n'
               f'  apiKey: "{key}",\n}});\n')
    findings = run_vendor_rules({"lib/openai.js": content})
    [f] = [f for f in findings if f.rule_id == KEY_RULE]
    assert f.start_line == 5
    t = triage(findings, {"lib/openai.js": content}, max_files=10, max_findings_per_file=30)
    [reported] = [x for x in t.passthrough if x.rule_id == KEY_RULE]
    assert reported.severity == Severity.HIGH and key not in reported.model_dump_json()
    assert 5 in t.masked_lines["lib/openai.js"]
    assert key not in content_for_model("lib/openai.js", content, [], t)
    assert "lib/openai.js" not in t.to_model or KEY_RULE not in [x.rule_id for x in t.to_model["lib/openai.js"]]


def test_a_placeholder_key_is_counted_not_reported():
    content = 'import OpenAI from "openai";\nconst c = new OpenAI({ apiKey: "your-api-key-here", timeout: 1 });\n'
    findings = run_vendor_rules({"demo.js": content})
    t = triage(findings, {"demo.js": content}, max_files=10, max_findings_per_file=30)
    assert [x for x in t.passthrough if x.rule_id == KEY_RULE] == [] and t.placeholders == 1


def test_python_is_never_handed_to_them():
    py = 'import anthropic\nclient = anthropic.Anthropic(api_key="sk-ant-xxxxxxxxxxxxxxxxxxxx")\n'
    assert run_vendor_rules({"app.py": py}) == []


def test_the_generic_agent_is_told_what_these_rules_are():
    from codeguard.pipeline.nodes import _SECURITY_GENERIC_SYSTEM_PROMPT
    assert "LLM" in _SECURITY_GENERIC_SYSTEM_PROMPT and "codeguard-js-llm-" in _SECURITY_GENERIC_SYSTEM_PROMPT
