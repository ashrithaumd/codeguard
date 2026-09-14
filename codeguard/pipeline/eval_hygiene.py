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

from codeguard.severity import Severity
from codeguard.tools.models import Finding

_AI_IMPORT_MARKERS = ("anthropic", "openai", "langchain", "langgraph")
_TEST_PATH_MARKERS = ("test_", "_test.py", "/tests/")
_MOCK_MARKERS = ("mock", "Mock", "monkeypatch", "@patch", "responses.", "vcr", "MagicMock", "AsyncMock")

# A "content=" or "system=" kwarg holding a >=200-char triple-quoted
# string literal — a real inline prompt, not a short placeholder. Not
# meant to catch every inline prompt, just the ones long enough that
# versioning them separately from code would plainly help.
_PROMPT_STRING_RE = re.compile(
    r'(?:content|system)\s*=\s*(?:f?"""[\s\S]{200,}?"""|f?\'\'\'[\s\S]{200,}?\'\'\')'
)


def _is_test_path(path: str) -> bool:
    lower = "/" + path.lower()
    return any(marker in lower for marker in _TEST_PATH_MARKERS)


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
