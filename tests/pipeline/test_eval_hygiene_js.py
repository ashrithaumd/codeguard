"""Eval hygiene for JavaScript/TypeScript: code that calls an LLM SDK in a
repository with nothing to catch a regression -- no evals/ directory, no
eval-framework files (promptfoo, evalite) and no test asserting on LLM
output. Python's check (review_eval_hygiene) is untouched and never sees a
JS/TS file.
"""

from __future__ import annotations

from unittest.mock import patch

from codeguard.pipeline.eval_hygiene import (
    JS_MISSING_EVALS,
    calls_llm_js,
    is_js_test_path,
    review_eval_hygiene,
    review_eval_hygiene_js,
)
from codeguard.severity import Severity
from codeguard.worker.main import MAX_JS_EVIDENCE_FILES, prepare_eval_hygiene_js

CHAT = 'import Anthropic from "@anthropic-ai/sdk";\nconst client = new Anthropic();\nexport const ask = (q) => client.messages.create({});\n'
SUMMARY = 'const OpenAI = require("openai");\nmodule.exports = new OpenAI();\n'
UTIL = 'export const add = (a: number, b: number) => a + b;\n'


def _one(findings):
    [f] = findings
    return f


def test_llm_code_with_nothing_to_catch_a_regression_is_one_repo_finding():
    sources = {"src/chat.ts": CHAT, "lib/summary.js": SUMMARY, "src/util.ts": UTIL}
    f = _one(review_eval_hygiene_js(sources, sources, sources))
    assert (f.file, f.start_line, f.source_tool, f.rule_id, f.severity) == (
        "<repo>", 0, "eval-hygiene", JS_MISSING_EVALS, Severity.MEDIUM)
    assert "2 JavaScript/TypeScript file(s)" in f.message
    assert "lib/summary.js, src/chat.ts" in f.message


def test_any_eval_signal_is_enough():
    sources = {"src/chat.ts": CHAT}
    asserting = 'import OpenAI from "openai";\nimport { vi } from "vitest";\nexpect(await run()).toContain("ok");\n'
    for paths, evidence in (
        (["src/chat.ts", "evals/cases.json"], {}),
        (["src/chat.ts", "packages/bot/evals/run.ts"], {}),
        (["src/chat.ts", "promptfooconfig.yaml"], {}),
        (["src/chat.ts", "src/chat.eval.ts"], {}),
        (["src/chat.ts", "src/__tests__/chat.test.ts"], {"src/__tests__/chat.test.ts": asserting}),
        (["src/chat.ts", "test/chat.spec.js"], {"test/chat.spec.js": asserting.replace("expect(", "assert.ok(")}),
    ):
        assert review_eval_hygiene_js(sources, evidence, paths) == [], paths


def test_a_test_that_never_asserts_on_llm_output_is_not_enough():
    sources = {"src/chat.ts": CHAT}
    no_llm = {"src/util.test.ts": 'import { add } from "./util";\nexpect(add(1, 2)).toBe(3);\n'}
    no_assert = {"src/chat.test.ts": 'import Anthropic from "@anthropic-ai/sdk";\nconsole.log("smoke");\n'}
    for evidence in (no_llm, no_assert):
        assert len(review_eval_hygiene_js(sources, evidence, [*sources, *evidence])) == 1


def test_what_counts_as_calling_an_llm():
    assert calls_llm_js(CHAT) and calls_llm_js(SUMMARY)
    for src in ('import { generateText } from "ai";', 'import { openai } from "@ai-sdk/openai";',
                'import { ChatOpenAI } from "@langchain/openai";', 'import "openai/shims/node";',
                'const { Anthropic } = await import("@anthropic-ai/sdk");'):
        assert calls_llm_js(src), src
    for src in ('import OpenAIIcon from "./openai-icon";', "// we used to call openai here",
                'const label = "anthropic";', 'import { aiHelpers } from "./ai";', UTIL):
        assert not calls_llm_js(src), src


def test_test_files_are_never_counted_as_llm_code():
    tests_only = {"src/chat.test.ts": CHAT, "__tests__/summary.js": SUMMARY, "src/chat.spec.tsx": CHAT}
    assert all(is_js_test_path(p) for p in tests_only)
    assert not is_js_test_path("src/latest.ts") and not is_js_test_path("src/contest.js")
    assert review_eval_hygiene_js(tests_only, tests_only, tests_only) == []


def test_python_eval_hygiene_is_untouched_by_js_files():
    py = {"app/chat.py": "import anthropic\nclient = anthropic.Anthropic()\n"}
    before = review_eval_hygiene(py)
    assert [f.rule_id for f in before] == ["eval-hygiene.missing-evals"]
    assert review_eval_hygiene_js(py, py, py) == []


# --- PR reviews ----------------------------------------------------------

async def test_a_pr_that_changes_no_llm_calling_js_fetches_nothing():
    with patch("codeguard.worker.main.get_repo_tree") as tree:
        assert await prepare_eval_hygiene_js("tok", "o", "r", "main", {}) == []
        assert await prepare_eval_hygiene_js("tok", "o", "r", "main", {"src/util.ts": UTIL, "Dockerfile": "FROM x"}) == []
    tree.assert_not_called()


async def test_a_pr_adding_llm_code_is_judged_against_the_base_branch():
    base_tree = [{"path": p, "type": "blob"} for p in
                 ("src/util.ts", "src/__tests__/util.test.ts", "src/__tests__/chat.test.ts", "README.md")]
    base = {"src/__tests__/chat.test.ts": 'import Anthropic from "@anthropic-ai/sdk";\nexpect(1).toBe(1);\n'}
    fetched = []

    def fetch(token, owner, repo, path, ref):
        fetched.append((path, ref))
        return base.get(path, "expect(1)")
    with patch("codeguard.worker.main.get_repo_tree", return_value=base_tree) as tree, \
         patch("codeguard.worker.main.get_file_content", side_effect=fetch):
        assert await prepare_eval_hygiene_js("tok", "o", "r", "main", {"src/chat.ts": CHAT}) == []
    assert tree.call_args.args[-1] == "main"
    # Only test files are fetched, and only at the base.
    assert sorted(fetched) == [("src/__tests__/chat.test.ts", "main"), ("src/__tests__/util.test.ts", "main")]

    with patch("codeguard.worker.main.get_repo_tree", return_value=base_tree[:2]), \
         patch("codeguard.worker.main.get_file_content", side_effect=fetch):
        [f] = await prepare_eval_hygiene_js("tok", "o", "r", "main", {"src/chat.ts": CHAT})
    assert f.rule_id == JS_MISSING_EVALS and "src/chat.ts" in f.message


async def test_the_evidence_fetch_is_capped_and_failures_say_nothing():
    many = [{"path": f"t/m{i}.test.ts", "type": "blob"} for i in range(MAX_JS_EVIDENCE_FILES + 5)]
    with patch("codeguard.worker.main.get_repo_tree", return_value=many), \
         patch("codeguard.worker.main.get_file_content", return_value="expect(1)") as content:
        await prepare_eval_hygiene_js("tok", "o", "r", "main", {"src/chat.ts": CHAT})
    assert content.call_count == MAX_JS_EVIDENCE_FILES
    # Eval hygiene is a soft signal: a failed tree listing is no finding.
    with patch("codeguard.worker.main.get_repo_tree", side_effect=RuntimeError("boom")):
        assert await prepare_eval_hygiene_js("tok", "o", "r", "main", {"src/chat.ts": CHAT}) == []
