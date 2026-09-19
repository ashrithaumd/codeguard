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
    MAX_CHUNK_TOKENS,
    MIN_CHUNK_TOKENS,
    _ast_chunk_boundaries,
    _chunk_file_by_ast,
    _clone_shallow,
    _collect_repo_files,
    _effective_chunk_budget,
    _is_remote_url,
    _load_local_repo_config,
    _parse_owner_repo,
    _run_verdict_layer,
    _select_files_for_audit,
    _synthetic_whole_file_patch,
    post_issue,
    render_report,
    run_audit,
)
from codeguard.config import RepoConfig, get_settings
from codeguard.pipeline.models import DismissedFinding, VerdictCallFailure
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
        skipped_files=[], verdict_call_failures=[], tokens_in=100, tokens_out=50, estimated_cost_usd=0.01, elapsed_s=1.5,
    )

    assert "# CodeGuard audit: foo/bar" in report
    assert "Critical" in report and "B608" in report
    assert "Low" in report and "E501" in report
    assert "hardcoded but a test fixture" in report
    assert "no eval suite found" in report
    assert "GHSA-xxx" in report
    assert "$0.0100" in report


def test_render_report_notes_skipped_files():
    report = render_report(
        target="x", files_scanned=1, files_ai_aware=0, ai_reviewed_findings=[], passthrough_findings=[],
        dismissed=[], eval_hygiene_findings=[], osv_findings=[],
        skipped_files=[("big.py", "dropped by audit_max_tokens_ceiling")], verdict_call_failures=[],
        tokens_in=0, tokens_out=0, estimated_cost_usd=0.0, elapsed_s=0.1,
    )
    assert "dropped before review by the audit budget ceiling" in report
    assert "## Skipped" in report
    assert "big.py" in report
    assert "dropped by audit_max_tokens_ceiling" in report


def test_render_report_notes_verdict_call_failures():
    report = render_report(
        target="x", files_scanned=1, files_ai_aware=1, ai_reviewed_findings=[], passthrough_findings=[],
        dismissed=[], eval_hygiene_findings=[], osv_findings=[],
        skipped_files=[], verdict_call_failures=[("huge.py", "lines 1-5000: agent call failed, raw finding(s) reported unverified")],
        tokens_in=0, tokens_out=0, estimated_cost_usd=0.0, elapsed_s=0.1,
    )
    assert "AI-verdict call(s) failed" in report
    assert "huge.py" in report


def test_render_report_zero_findings_says_so():
    report = render_report(
        target="x", files_scanned=2, files_ai_aware=0, ai_reviewed_findings=[], passthrough_findings=[],
        dismissed=[], eval_hygiene_findings=[], osv_findings=[], skipped_files=[], verdict_call_failures=[],
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
        exit_code, error = run_audit(str(tmp_path), str(output), post_issue_flag=False)

    assert exit_code == 0
    assert error is None
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
        exit_code, error = run_audit(str(tmp_path), str(output), post_issue_flag=False)

    assert exit_code == 0
    mock_aa.assert_not_called()
    report = output.read_text(encoding="utf-8")
    assert "llm-unpinned-model-alias" in report  # still reported, just as passthrough not a verdict


def test_run_audit_rejects_a_target_that_is_neither_url_nor_dir(tmp_path):
    missing = tmp_path / "does-not-exist"
    exit_code, error = run_audit(str(missing), str(tmp_path / "report.md"), post_issue_flag=False)
    assert exit_code == 1
    assert error is not None and "not a directory" in error


# --- File selection order + AST chunking for oversized files ---

def test_select_files_for_audit_prioritizes_ai_touching_over_non_ai():
    all_files = {
        "big_ai.py": "import anthropic\n" + "x = 1\n" * 50,
        "small_plain.py": "y = 2\n",
    }
    selected, skipped = _select_files_for_audit(all_files, max_files=1, max_tokens=1_000_000)

    assert set(selected) == {"big_ai.py"}
    assert skipped == [("small_plain.py", "dropped by audit_max_files_ceiling")]


def test_select_files_for_audit_prefers_smaller_within_the_same_group():
    all_files = {
        "plain_big.py": "x = 1\n" * 500,
        "plain_small.py": "y = 2\n",
    }
    selected, skipped = _select_files_for_audit(all_files, max_files=1, max_tokens=1_000_000)

    assert set(selected) == {"plain_small.py"}
    assert skipped == [("plain_big.py", "dropped by audit_max_files_ceiling")]


def test_select_files_for_audit_respects_token_ceiling():
    all_files = {"a.py": "x = 1\n" * 10, "b.py": "y = 2\n" * 10, "c.py": "z = 3\n" * 10}
    tiny_budget = 15  # smaller than two files combined, larger than one

    selected, skipped = _select_files_for_audit(all_files, max_files=10, max_tokens=tiny_budget)

    assert len(selected) < 3
    assert len(skipped) > 0
    assert all(reason == "dropped by audit_max_tokens_ceiling" for _, reason in skipped)


def test_select_files_for_audit_always_includes_at_least_one_file():
    """Mirrors apply_token_budget's own rule (diff/ingest.py): an empty
    audit because the very first (smallest) file already exceeds the
    token ceiling on its own is worse than reviewing that one file."""
    all_files = {"only.py": "x = 1\n" * 1000}
    selected, skipped = _select_files_for_audit(all_files, max_files=10, max_tokens=1)

    assert set(selected) == {"only.py"}
    assert skipped == []


def test_chunk_file_by_ast_returns_whole_file_when_it_fits():
    content = "x = 1\ny = 2\n"
    assert _chunk_file_by_ast(content, max_tokens=1000) == [(1, 2)]


def test_chunk_file_by_ast_returns_none_for_unparseable_content():
    assert _chunk_file_by_ast("def f(:\n    pass\n" * 2000, max_tokens=5) is None


def test_chunk_file_by_ast_splits_at_function_boundaries_and_covers_every_line():
    content = "\n".join(f"def f{i}():\n    return {i}\n" for i in range(20))
    total_lines = len(content.splitlines())

    boundaries = _chunk_file_by_ast(content, max_tokens=10)

    assert boundaries is not None
    assert len(boundaries) > 1  # actually split, not one giant chunk
    # every line belongs to exactly one chunk, in order, no gaps/overlaps
    assert boundaries[0][0] == 1
    assert boundaries[-1][1] == total_lines
    for (_, end), (next_start, _) in zip(boundaries, boundaries[1:]):
        assert next_start == end + 1


def test_chunk_file_by_ast_recurses_into_one_oversized_class():
    methods = "\n".join(f"    def m{i}(self):\n        return {i}\n" for i in range(20))
    content = f"class Big:\n{methods}"

    boundaries = _chunk_file_by_ast(content, max_tokens=10)

    assert boundaries is not None
    assert len(boundaries) > 1  # the single ClassDef alone exceeds budget; recursed into its methods


def test_ast_chunk_boundaries_direct_on_module_body():
    import ast as ast_module
    content = "def a():\n    pass\ndef b():\n    pass\n"
    tree = ast_module.parse(content)
    lines = content.splitlines()

    boundaries = _ast_chunk_boundaries(tree.body, lines, max_tokens=1)

    assert len(boundaries) == 2  # each function forced into its own chunk


def test_effective_chunk_budget_shrinks_as_findings_grow():
    """Found live against simonw/llm's tests/test_logs_store.py: a file
    whose content alone looked safely under a flat chunk budget still
    got refused once its ~280-finding block was appended — the budget
    must leave room for that block, not just the content."""
    few = [_finding(line=i) for i in range(2)]
    many = [_finding(line=i) for i in range(200)]

    assert _effective_chunk_budget(many) < _effective_chunk_budget(few)


def test_effective_chunk_budget_floors_at_min_chunk_tokens():
    huge_findings = [_finding(line=i, message="x" * 500) for i in range(500)]
    assert _effective_chunk_budget(huge_findings) == MIN_CHUNK_TOKENS


def test_effective_chunk_budget_stays_under_max_chunk_tokens_even_for_no_findings():
    assert _effective_chunk_budget([]) < MAX_CHUNK_TOKENS


def _mock_verdict_ok(findings):
    return {"findings": findings, "dismissed_findings": [], "tokens_in": 5, "tokens_out": 2, "estimated_cost_usd": 0.001}


def test_run_verdict_layer_makes_one_call_for_a_small_file():
    f = _finding(file="a.py", line=1)
    files = {"a.py": "x = 1\n"}
    mock_fn = lambda state: _mock_verdict_ok(state["findings"])

    confirmed, dismissed, ti, to, cost, failures = _run_verdict_layer(mock_fn, "o", "r", files, {"a.py": [f]})

    assert confirmed == [f]
    assert failures == []
    assert ti == 5 and to == 2


def test_run_verdict_layer_chunks_an_oversized_file_and_attributes_findings_by_line():
    content = "\n".join(f"def f{i}():\n    return {i}\n" for i in range(20))
    f_early = _finding(file="big.py", line=2, rule_id="B105")
    f_late = _finding(file="big.py", line=len(content.splitlines()) - 1, rule_id="B608")
    files = {"big.py": content}
    calls = []

    def mock_fn(state):
        calls.append((state["content"], [f.rule_id for f in state["findings"]]))
        return _mock_verdict_ok(state["findings"])

    with patch("codeguard.cli._effective_chunk_budget", return_value=10):
        confirmed, dismissed, ti, to, cost, failures = _run_verdict_layer(
            mock_fn, "o", "r", files, {"big.py": [f_early, f_late]},
        )

    assert len(calls) > 1  # actually split into multiple chunk calls
    assert {f.rule_id for f in confirmed} == {"B105", "B608"}
    assert failures == []


def test_run_verdict_layer_records_the_failure_the_node_reports():
    """The node reports its own failure via verdict_call_failures,
    carrying AgentCallResult.error verbatim; this layer adds the chunk's
    line range and surfaces it in the report's Skipped section.
    """
    f = _finding(file="a.py", line=1)
    files = {"a.py": "x = 1\n"}
    def mock_fn(state):
        return {
            "findings": state["findings"],
            "node_latencies": [],
            "verdict_call_failures": [
                VerdictCallFailure(path="a.py", agent="security", reason="output failed validation (empty/degenerate)")
            ],
        }

    result = _run_verdict_layer(mock_fn, "o", "r", files, {"a.py": [f]})

    assert result.confirmed == [f]  # raw finding still reported, unverified
    assert len(result.call_failures) == 1
    path, reason = result.call_failures[0]
    assert path == "a.py"
    assert "security call failed" in reason
    assert "output failed validation" in reason  # the real error, not a re-derived description


def test_run_verdict_layer_detects_a_failure_that_still_carries_token_counts():
    """The specific bug the old implementation had: failure used to be
    inferred from the ABSENCE of a "tokens_in" key, so any failure path
    that happened to report token counts was silently read as success.
    A node reporting both is now still recognised as a failure.
    """
    f = _finding(file="a.py", line=1)
    files = {"a.py": "x = 1\n"}
    def mock_fn(state):
        return {
            "findings": state["findings"],
            "tokens_in": 12, "tokens_out": 0, "estimated_cost_usd": 0.0,
            "verdict_call_failures": [VerdictCallFailure(path="a.py", agent="security", reason="boom")],
        }

    result = _run_verdict_layer(mock_fn, "o", "r", files, {"a.py": [f]})

    assert len(result.call_failures) == 1
    assert result.tokens_in == 12  # still accounted for, not discarded


def test_run_verdict_layer_reports_no_failure_on_a_clean_call():
    """The mirror of the above: a successful call carries no
    verdict_call_failures, and nothing is invented for it.
    """
    f = _finding(file="a.py", line=1)
    files = {"a.py": "x = 1\n"}

    result = _run_verdict_layer(lambda state: _mock_verdict_ok(state["findings"]), "o", "r", files, {"a.py": [f]})

    assert result.call_failures == []
    assert result.confirmed == [f]


def test_run_verdict_layer_reports_unparseable_file_as_a_call_failure():
    files = {"bad.py": "def f(:\n"}
    f = _finding(file="bad.py", line=1)
    mock_fn = lambda state: _mock_verdict_ok(state["findings"])

    with patch("codeguard.cli._effective_chunk_budget", return_value=1):
        confirmed, dismissed, ti, to, cost, failures = _run_verdict_layer(mock_fn, "o", "r", files, {"bad.py": [f]})

    assert any("not parseable as Python" in reason for _, reason in failures)
