"""Regression coverage for codeguard/cli.py — the pure helpers directly,
plus one orchestration test for run_audit with every LLM/network call
mocked (review_security, review_ai_aware, run_tools_on_files,
check_dependency_updates), since the passthrough/claiming logic between
those calls is exactly the kind of bug live testing wouldn't reliably
surface (it depends on which files happen to have which finding types).
"""

from __future__ import annotations

from unittest.mock import patch

from codeguard.cli import (
    _clone_shallow,
    _collect_repo_files,
    _is_remote_url,
    _load_local_repo_config,
    _parse_owner_repo,
    _synthetic_whole_file_patch,
    post_issue,
    render_report,
    run_audit,
)
from codeguard.config import RepoConfig, get_settings
from codeguard.pipeline.models import DismissedFinding
from codeguard.severity import Severity
from codeguard.tools.models import Finding


def _finding(file="a.py", line=1, tool="bandit", rule_id="B105", message="x", severity=Severity.HIGH):
    return Finding.create(file=file, start_line=line, end_line=line, severity=severity, source_tool=tool, rule_id=rule_id, message=message)


def test_is_remote_url():
    assert _is_remote_url("https://github.com/foo/bar")
    assert _is_remote_url("git@github.com:foo/bar.git")
    assert not _is_remote_url("C:/Users/me/repo")
    assert not _is_remote_url("./local/repo")


def test_synthetic_whole_file_patch_header_covers_every_line():
    patch_text = _synthetic_whole_file_patch("a\nb\nc\n")
    assert patch_text == "@@ -0,0 +1,3 @@"


def test_synthetic_whole_file_patch_handles_empty_content():
    assert _synthetic_whole_file_patch("") == "@@ -0,0 +1,1 @@"


def test_parse_owner_repo_from_https_and_ssh_and_dotgit():
    assert _parse_owner_repo("https://github.com/foo/bar") == ("foo", "bar")
    assert _parse_owner_repo("https://github.com/foo/bar.git") == ("foo", "bar")
    assert _parse_owner_repo("git@github.com:foo/bar.git") == ("foo", "bar")


def test_parse_owner_repo_none_for_non_github():
    assert _parse_owner_repo("/local/path") is None
    assert _parse_owner_repo("https://gitlab.com/foo/bar") is None


def test_collect_repo_files_classifies_python_manifest_and_vendored(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("docs\n", encoding="utf-8")
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    (vendor_dir / "lib.py").write_text("y = 2\n", encoding="utf-8")

    files, dep_contents, dep_patches = _collect_repo_files(tmp_path, RepoConfig())

    assert files == {"app.py": "x = 1\n"}
    assert dep_contents == {"requirements.txt": "pyyaml==5.3\n"}
    assert dep_patches == {"requirements.txt": "@@ -0,0 +1,1 @@"}


def test_collect_repo_files_respects_repo_config_ignored_paths(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "generated.py").write_text("y = 2\n", encoding="utf-8")

    files, _, _ = _collect_repo_files(tmp_path, RepoConfig(ignored_paths=["generated.py"]))

    assert files == {"app.py": "x = 1\n"}


def test_load_local_repo_config_defaults_to_audit_ceiling_when_no_file(tmp_path):
    settings = get_settings()
    cfg = _load_local_repo_config(tmp_path, settings)
    assert cfg.max_files_per_pr == settings.audit_max_files_ceiling
    assert cfg.max_tokens_per_pr == settings.audit_max_tokens_ceiling


def test_load_local_repo_config_reads_real_codeguard_yml(tmp_path):
    (tmp_path / ".codeguard.yml").write_text("enable_ai_aware: false\nmax_files_per_pr: 5\n", encoding="utf-8")
    cfg = _load_local_repo_config(tmp_path, get_settings())
    assert cfg.enable_ai_aware is False
    assert cfg.max_files_per_pr == 5


def test_load_local_repo_config_falls_back_on_invalid_yaml(tmp_path):
    (tmp_path / ".codeguard.yml").write_text("not: valid: yaml: [", encoding="utf-8")
    settings = get_settings()
    cfg = _load_local_repo_config(tmp_path, settings)
    assert cfg.max_files_per_pr == settings.audit_max_files_ceiling


def test_render_report_groups_by_severity_and_includes_all_sections():
    report = render_report(
        target="foo/bar", files_scanned=3, files_ai_aware=1,
        ai_reviewed_findings=[_finding(severity=Severity.CRITICAL, rule_id="B608")],
        passthrough_findings=[_finding(file="b.py", severity=Severity.LOW, tool="ruff", rule_id="E501")],
        dismissed=[DismissedFinding(file="c.py", start_line=2, rule_id="B105", reason="hardcoded but a test fixture")],
        eval_hygiene_findings=[_finding(file="d.py", tool="eval-hygiene", rule_id="no-eval-harness", message="no eval suite found")],
        osv_findings=[_finding(file="requirements.txt", tool="osv", rule_id="GHSA-xxx", severity=Severity.HIGH)],
        budget_exceeded=False, tokens_in=100, tokens_out=50, estimated_cost_usd=0.01, elapsed_s=1.5,
    )

    assert "# CodeGuard audit: foo/bar" in report
    assert "Critical" in report and "B608" in report
    assert "Low" in report and "E501" in report
    assert "hardcoded but a test fixture" in report
    assert "no eval suite found" in report
    assert "GHSA-xxx" in report
    assert "$0.0100" in report


def test_render_report_notes_budget_exceeded():
    report = render_report(
        target="x", files_scanned=1, files_ai_aware=0, ai_reviewed_findings=[], passthrough_findings=[],
        dismissed=[], eval_hygiene_findings=[], osv_findings=[], budget_exceeded=True,
        tokens_in=0, tokens_out=0, estimated_cost_usd=0.0, elapsed_s=0.1,
    )
    assert "exceeded the audit budget ceiling" in report


def test_render_report_zero_findings_says_so():
    report = render_report(
        target="x", files_scanned=2, files_ai_aware=0, ai_reviewed_findings=[], passthrough_findings=[],
        dismissed=[], eval_hygiene_findings=[], osv_findings=[], budget_exceeded=False,
        tokens_in=0, tokens_out=0, estimated_cost_usd=0.0, elapsed_s=0.1,
    )
    assert "No findings." in report


def test_post_issue_posts_and_returns_url():
    with patch("codeguard.cli.requests.post") as mock_post:
        mock_post.return_value.json.return_value = {"html_url": "https://github.com/o/r/issues/1"}
        mock_post.return_value.raise_for_status.return_value = None
        url = post_issue("tok", "o", "r", "report body")

    assert url == "https://github.com/o/r/issues/1"
    kwargs = mock_post.call_args.kwargs
    assert kwargs["json"]["body"] == "report body"
    assert kwargs["headers"]["Authorization"] == "Bearer tok"


def _mock_verdict_result(findings, dismissed=None):
    return {"findings": findings, "dismissed_findings": dismissed or [], "tokens_in": 5, "tokens_out": 2, "estimated_cost_usd": 0.001}


def test_run_audit_end_to_end_orchestration(tmp_path):
    """Everything network/LLM is mocked; this is exercising the
    orchestration: passthrough claiming, budget wiring, report writing.
    """
    (tmp_path / "secure.py").write_text("import subprocess\nsubprocess.call(cmd, shell=True)\n", encoding="utf-8")
    (tmp_path / "assistant.py").write_text("import anthropic\nclient = anthropic.Anthropic()\n", encoding="utf-8")
    (tmp_path / "plain.py").write_text("def add(a, b):\n    return a+b\n", encoding="utf-8")
    output = tmp_path / "report.md"

    bandit_finding = _finding(file="secure.py", tool="bandit", rule_id="B602", severity=Severity.HIGH)
    ruff_finding = _finding(file="plain.py", tool="ruff", rule_id="E731", severity=Severity.LOW)
    semgrep_finding = _finding(file="assistant.py", tool="semgrep", rule_id="llm-unpinned-model-alias", severity=Severity.MEDIUM)

    async def _fake_run_tools(files, patches):
        return [bandit_finding, ruff_finding, semgrep_finding]

    with patch("codeguard.cli.run_tools_on_files", side_effect=_fake_run_tools), \
         patch("codeguard.cli.check_dependency_updates", return_value=[]), \
         patch("codeguard.cli.review_eval_hygiene", return_value=[]), \
         patch("codeguard.cli.review_security", return_value=_mock_verdict_result([bandit_finding])) as mock_sec, \
         patch("codeguard.cli.review_ai_aware", return_value=_mock_verdict_result([semgrep_finding])) as mock_aa:
        exit_code = run_audit(str(tmp_path), str(output), post_issue_flag=False)

    assert exit_code == 0
    mock_sec.assert_called_once()
    mock_aa.assert_called_once()

    report = output.read_text(encoding="utf-8")
    assert "B602" in report          # bandit finding, claimed by review_security, still shown
    assert "E731" in report          # ruff finding, always passthrough
    assert "llm-unpinned-model-alias" in report  # semgrep on an AI file, claimed by review_ai_aware
    assert "$0.0020" in report       # 0.001 + 0.001 combined cost


def test_run_audit_skips_ai_aware_when_disabled(tmp_path):
    (tmp_path / ".codeguard.yml").write_text("enable_ai_aware: false\n", encoding="utf-8")
    (tmp_path / "assistant.py").write_text("import anthropic\n", encoding="utf-8")
    output = tmp_path / "report.md"

    semgrep_finding = _finding(file="assistant.py", tool="semgrep", rule_id="llm-unpinned-model-alias")

    async def _fake_run_tools(files, patches):
        return [semgrep_finding]

    with patch("codeguard.cli.run_tools_on_files", side_effect=_fake_run_tools), \
         patch("codeguard.cli.check_dependency_updates", return_value=[]), \
         patch("codeguard.cli.review_ai_aware") as mock_aa:
        exit_code = run_audit(str(tmp_path), str(output), post_issue_flag=False)

    assert exit_code == 0
    mock_aa.assert_not_called()
    report = output.read_text(encoding="utf-8")
    assert "llm-unpinned-model-alias" in report  # still reported, just as passthrough not a verdict


def test_run_audit_rejects_a_target_that_is_neither_url_nor_dir(tmp_path):
    missing = tmp_path / "does-not-exist"
    exit_code = run_audit(str(missing), str(tmp_path / "report.md"), post_issue_flag=False)
    assert exit_code == 1
