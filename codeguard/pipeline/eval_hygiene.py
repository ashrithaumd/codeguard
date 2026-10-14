"""Repo-level "eval hygiene" checks for AI-aware code — run once per PR
against the base tree (see codeguard/github/base_tree.py), not the PR
diff, since these describe properties of the repo as a whole (does it
have an eval harness at all?), not what changed in this one PR.

Deliberately heuristic (substring/regex over file content), not
AST-based static analysis — that's Semgrep's job (rules/llm-security.yaml).
These three checks are about repo *practices* around LLM code, which
don't reduce to a single line-level pattern the way "no max_tokens" does.

Pure function of already-fetched content -> Finding list, no I/O here —
mirrors the rest of codeguard/pipeline/: all GitHub calls happen in
worker/main.py before the graph runs; nodes and their helpers only
transform state that's already in memory.
"""

from __future__ import annotations

import re

from codeguard.diff.filters import is_test_path
from codeguard.severity import Severity
from codeguard.tools.models import Finding

_AI_IMPORT_MARKERS = ("anthropic", "openai", "langchain", "langgraph")
_MOCK_MARKERS = ("mock", "Mock", "monkeypatch", "@patch", "responses.", "vcr", "MagicMock", "AsyncMock")

# A "content=" or "system=" kwarg holding a >=200-char triple-quoted
# string literal — a real inline prompt, not a short placeholder. Not
# meant to catch every inline prompt, just the ones long enough that
# versioning them separately from code would plainly help.
_PROMPT_STRING_RE = re.compile(
    r'(?:content|system)\s*=\s*(?:f?"""[\s\S]{200,}?"""|f?\'\'\'[\s\S]{200,}?\'\'\')'
)


def _is_test_path(path: str) -> bool:
    return is_test_path(path)


def _touches_ai(content: str) -> bool:
    return any(marker in content for marker in _AI_IMPORT_MARKERS)


def _repo_finding(severity: Severity, rule_id: str, message: str) -> Finding:
    return Finding.create(
        file="<repo>", start_line=0, end_line=0, severity=severity,
        source_tool="eval-hygiene", rule_id=rule_id, message=message,
    )


def review_eval_hygiene(base_tree_files: dict[str, str]) -> list[Finding]:
    if not base_tree_files:
        return []

    findings: list[Finding] = []

    has_evals_dir = any(path.startswith("evals/") for path in base_tree_files)
    has_prompts_dir = any(path.startswith("prompts/") for path in base_tree_files)

    llm_source_paths = sorted(
        path for path, content in base_tree_files.items()
        if not _is_test_path(path) and _touches_ai(content)
    )
    test_paths_with_ai = [
        path for path, content in base_tree_files.items()
        if _is_test_path(path) and _touches_ai(content)
    ]
    output_asserting_tests = [path for path in test_paths_with_ai if "assert" in base_tree_files[path]]

    if llm_source_paths and not has_evals_dir and not output_asserting_tests:
        shown = ", ".join(llm_source_paths[:5]) + ("..." if len(llm_source_paths) > 5 else "")
        findings.append(_repo_finding(
            Severity.MEDIUM, "eval-hygiene.missing-evals",
            f"{len(llm_source_paths)} file(s) call an LLM SDK ({shown}) but this repo has no "
            "evals/ directory and no test asserts on LLM output. LLM-calling code changes "
            "behavior silently (model updates, prompt edits) with nothing to catch a "
            "regression — add ground-truth eval fixtures or output-asserting tests.",
        ))

    live_call_tests = sorted(
        path for path in test_paths_with_ai
        if not any(marker in base_tree_files[path] for marker in _MOCK_MARKERS)
    )
    if live_call_tests:
        findings.append(_repo_finding(
            Severity.MEDIUM, "eval-hygiene.live-llm-calls-in-tests",
            f"Test file(s) {', '.join(live_call_tests)} call an LLM SDK with no mock/patch/"
            "fixture marker in the file — these tests likely hit a real LLM API on every CI "
            "run: non-deterministic, costs real money, and fails offline. Mock the client or "
            "record/replay fixtures instead.",
        ))

    inline_prompt_paths = sorted(
        path for path, content in base_tree_files.items()
        if not _is_test_path(path) and _PROMPT_STRING_RE.search(content)
    )
    if inline_prompt_paths and not has_prompts_dir:
        shown = ", ".join(inline_prompt_paths[:5]) + ("..." if len(inline_prompt_paths) > 5 else "")
        findings.append(_repo_finding(
            Severity.LOW, "eval-hygiene.unversioned-inline-prompts",
            f"{len(inline_prompt_paths)} file(s) ({shown}) embed long prompt strings directly "
            "in source, with no prompts/ directory in the repo. Inline prompts can't be "
            "diffed/reviewed/versioned independently of code changes, making it hard to tell "
            "a prompt-wording change from a logic change in a PR — move prompts to versioned "
            "files.",
        ))

    return findings


# --- JavaScript/TypeScript ------------------------------------------------
#
# The same question as missing-evals above, asked of JS/TS code with its
# own markers, and kept apart from it: review_eval_hygiene never sees a
# JS/TS file, so Python's findings are exactly what they were. One check
# only -- the live-call and inline-prompt checks stay Python's.

JS_MISSING_EVALS = "eval-hygiene.missing-evals-js"

_JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
# An import or require of an LLM SDK -- the statement, not the word, so a
# comment, a string or "./openai-icon" is not a call.
_JS_LLM_IMPORT_RE = re.compile(
    r"""(?:\bfrom\s+|\brequire\(\s*|\bimport\(\s*|\bimport\s+)["']"""
    r"""(?:openai|@anthropic-ai/sdk|ai|@ai-sdk/[\w.-]+|langchain|@langchain/[\w.-]+)(?:/[\w./-]*)?["']"""
)
_JS_TEST_DIRS = {"test", "tests", "__tests__", "__mocks__", "spec", "e2e"}
_JS_ASSERT_RE = re.compile(r"\bexpect\(|\bassert\b")
_PROMPTFOO_CONFIG_RE = re.compile(r"^promptfoo(?:config|\.config)\.(?:ya?ml|json|[cm]?[jt]s)$", re.IGNORECASE)
_EVALITE_RE = re.compile(r"\.eval\.(?:[cm]?[jt]sx?)$")


def _is_js(path: str) -> bool:
    return path.lower().endswith(_JS_EXTENSIONS)


def is_js_test_path(path: str) -> bool:
    """A JS/TS test file: under a test directory, or *.test.* / *.spec.*."""
    parts = path.replace("\\", "/").lower().split("/")
    name = parts[-1]
    return any(p in _JS_TEST_DIRS for p in parts[:-1]) or ".test." in name or ".spec." in name


def calls_llm_js(content: str) -> bool:
    return bool(_JS_LLM_IMPORT_RE.search(content))


def _has_js_eval_signal(evidence: dict[str, str], paths) -> bool:
    for path in paths:
        p = path.replace("\\", "/")
        name = p.rsplit("/", 1)[-1]
        if p.startswith("evals/") or "/evals/" in p or _PROMPTFOO_CONFIG_RE.match(name) or _EVALITE_RE.search(name):
            return True
    return any(
        _is_js(path) and is_js_test_path(path) and calls_llm_js(content) and _JS_ASSERT_RE.search(content)
        for path, content in evidence.items()
    )


def review_eval_hygiene_js(sources: dict[str, str], evidence: dict[str, str], paths) -> list[Finding]:
    """`sources`: JS/TS files that may call an LLM. `evidence`: file
    contents to look for output-asserting tests in. `paths`: every path in
    the repository, for evals/, promptfoo and evalite files. An audit passes
    the whole repository for all three; a PR passes its changed files as
    `sources` and the BASE branch's for the other two (worker/main.py), as
    Python's check reads the base."""
    llm_paths = sorted(p for p, c in sources.items() if _is_js(p) and not is_js_test_path(p) and calls_llm_js(c))
    if not llm_paths or _has_js_eval_signal(evidence, paths):
        return []
    shown = ", ".join(llm_paths[:5]) + ("..." if len(llm_paths) > 5 else "")
    return [_repo_finding(
        Severity.MEDIUM, JS_MISSING_EVALS,
        f"{len(llm_paths)} JavaScript/TypeScript file(s) call an LLM SDK ({shown}) but this repo has no "
        "evals/ directory, no eval-framework files (promptfoo, evalite) and no test that asserts on LLM "
        "output. LLM-calling code changes behavior silently (model updates, prompt edits) with nothing "
        "to catch a regression -- add ground-truth eval cases or output-asserting tests.",
    )]
