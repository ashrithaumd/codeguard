"""Audits: JS/TS eval hygiene over the whole repository, beside Python's
check, and only when the AI-aware checks are on."""

from __future__ import annotations

from unittest.mock import patch

from codeguard.cli import run_audit
from codeguard.tools.osv_runner import DependencyCheck

CHAT = 'import Anthropic from "@anthropic-ai/sdk";\nconst client = new Anthropic({ timeout: 1 });\nexport const c = client;\n'


def _run(root):
    output = root.parent / "report.md"
    patches = [patch("codeguard.cli.check_dependency_updates_status", return_value=DependencyCheck([])),
               patch("codeguard.cli.scan_lockfiles", return_value=DependencyCheck([])),
               patch("codeguard.cli.review_security_generic", side_effect=lambda s: {"findings": [], "dismissed_findings": []}),
               patch("codeguard.cli.review_security", return_value={"findings": []}),
               patch("codeguard.cli.review_ai_aware", return_value={"findings": []})]
    for p in patches:
        p.start()
    try:
        exit_code, error = run_audit(str(root), str(output), post_issue_flag=False)
    finally:
        for p in patches:
            p.stop()
    return exit_code, error, output.read_text(encoding="utf-8") if output.exists() else ""


def test_js_llm_code_with_no_evals_is_reported(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "chat.ts").write_text(CHAT)
    exit_code, error, report = _run(root)
    assert (exit_code, error) == (0, None)
    assert "1 JavaScript/TypeScript file(s) call an LLM SDK (src/chat.ts)" in report


def test_an_evals_directory_is_enough(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "evals").mkdir()
    (root / "src" / "chat.ts").write_text(CHAT)
    (root / "evals" / "cases.json").write_text("[]")
    _, _, report = _run(root)
    assert "JavaScript/TypeScript file(s)" not in report


def test_a_python_only_audit_has_no_js_finding(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("import anthropic\nclient = anthropic.Anthropic()\n")
    _, _, report = _run(root)
    assert "JavaScript/TypeScript file(s)" not in report
    assert "1 file(s) call an LLM SDK (app.py)" in report  # Python's own, unchanged


def test_the_first_line_counts_llm_sdk_files_in_every_language_with_ai_aware_rules(tmp_path):
    # It said "0 with an LLM SDK import" on a JavaScript repository whose LLM
    # code the JS rules had just reviewed. Python and JS/TS are the languages
    # with LLM-SDK detection and AI-aware rules; a test file is not counted.
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "chat.ts").write_text(CHAT)
    (root / "src" / "chat.test.ts").write_text(CHAT)
    (root / "src" / "util.ts").write_text("export const one = 1;\n")
    (root / "app.py").write_text("import anthropic\nclient = anthropic.Anthropic()\n")
    _, _, report = _run(root)
    assert "(2 with an LLM SDK import, reviewed for AI-aware issues)" in report


def test_a_python_only_audit_counts_as_before(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("import anthropic\nclient = anthropic.Anthropic()\n")
    (root / "util.py").write_text("ONE = 1\n")
    _, _, report = _run(root)
    assert "(1 with an LLM SDK import, reviewed for AI-aware issues)" in report
