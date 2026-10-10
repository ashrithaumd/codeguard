"""Audits of JS/TS, Go, Java and C# code: the vendored rules, the triage,
and the security_generic agent (mocked here; no live call).

A repository with no Python but JS/Go code is audited now, not rejected. A
Python-only audit is exactly what it was: the agent is never called and no
model row is added. What reaches the agent has the secrets scan's spans
masked. The file cap holds, and what it leaves out is listed.
"""

from __future__ import annotations

import random
import string
from unittest.mock import patch

from codeguard.cli import run_audit
from codeguard.config import Settings, get_settings
from codeguard.pipeline.models import DismissedFinding  # noqa: F401 -- shape reference for the mock below

JS_EVAL = "function run(userInput) {\n  return eval(userInput);\n}\n"


def _verdict(state):
    """Confirms everything it is given, at the finding's own severity."""
    return {"findings": [f.model_copy(update={"source_tool": "security_generic"}) for f in state["findings"]],
            "dismissed_findings": [], "tokens_in": 100, "tokens_out": 10, "estimated_cost_usd": 0.001}


def _settings(**over):
    base = get_settings().model_dump()
    base.update(over)
    return Settings(**base)


def _run(tmp_path, **settings_over):
    seen = []

    def fake(state):
        seen.append(state)
        return _verdict(state)

    output = tmp_path / "report.md"
    with patch("codeguard.cli.review_security_generic", side_effect=fake), \
         patch("codeguard.cli.check_dependency_updates", return_value=[]), \
         patch("codeguard.cli.get_settings", return_value=_settings(**settings_over)):
        exit_code, error = run_audit(str(tmp_path), str(output), post_issue_flag=False)
    return exit_code, error, output.read_text(encoding="utf-8") if output.exists() else "", seen


def test_a_js_only_repository_is_audited_not_rejected(tmp_path):
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "run.js").write_text(JS_EVAL)
    exit_code, error, report, seen = _run(tmp_path)
    assert (exit_code, error) == (0, None)
    assert [s["path"] for s in seen] == ["web/run.js"]
    assert "eval" in report.lower() and "web/run.js" in report


def test_a_python_only_audit_never_calls_the_generic_agent(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    with patch("codeguard.cli.review_security", return_value={"findings": []}), \
         patch("codeguard.cli.review_ai_aware", return_value={"findings": []}):
        exit_code, _, report, seen = _run(tmp_path)
    assert exit_code == 0 and seen == []
    assert "security_generic" not in report


def test_the_audit_file_cap_holds_and_lists_the_rest(tmp_path):
    for name in ("a.js", "b.js", "c.js"):
        (tmp_path / name).write_text(JS_EVAL)
    _, _, report, seen = _run(tmp_path, generic_ai_files_per_audit=1)
    assert len(seen) == 1
    assert report.count("not reviewed by AI (cap: 1 files)") == 2


def test_what_reaches_the_agent_has_secrets_masked(tmp_path):
    rng = random.Random(5)
    key = "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))
    (tmp_path / "run.js").write_text(f'const token = "{key}";\n' + JS_EVAL)
    _, _, report, seen = _run(tmp_path)
    [state] = seen
    assert key not in state["content"] and "[redacted]" in state["content"]
    assert key not in report


def test_an_oversized_file_is_listed_not_scanned(tmp_path):
    (tmp_path / "big.js").write_text(JS_EVAL + "// pad\n" * 60000)
    (tmp_path / "run.js").write_text(JS_EVAL)
    _, _, report, seen = _run(tmp_path)
    assert [s["path"] for s in seen] == ["run.js"]
    assert "big.js" in report and "too large to scan" in report


def test_the_rejection_names_the_covered_languages_and_the_not_covered_list():
    from codeguard.cli import NO_COVERED_CODE_MESSAGE
    for name in ("Python", "JavaScript/TypeScript", "Go", "Java", "C#",
                 "configuration", "secret", "dependency", "not covered"):
        assert name in NO_COVERED_CODE_MESSAGE, name
    assert "currently analyzes Python repositories" not in NO_COVERED_CODE_MESSAGE
