"""Regression coverage for codeguard/mcp/server.py's local-diff ingestion
— built against a real throwaway git repo (subprocess git, not mocked),
since the whole point of this module is translating `git status`/
`git diff` output into the same shape diff/ingest.py builds from the
GitHub API, and that translation is exactly what a mock would hide bugs
in. review_diff/audit_repo themselves (the actual LLM/pipeline calls)
are exercised live, not here — see evals/RESULTS.md instead.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from codeguard.config import RepoConfig, get_settings, effective_budget
from codeguard.mcp.server import (
    GitError,
    _git_changed_paths,
    _git_repo_root,
    _ingest_local_diff,
    _run_review_diff,
    _serialize_dismissed,
    _serialize_finding,
)
from codeguard.pipeline.models import DismissedFinding
from codeguard.severity import Severity
from codeguard.tools.models import Finding


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)


def _init_repo(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "test@example.com")
    _git(tmp_path, "config", "user.name", "Test")
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-q", "-m", "initial")
    return tmp_path


def test_git_changed_paths_sees_tracked_modification(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")

    changed = _git_changed_paths(tmp_path)

    assert changed == [("app.py", False)]


def test_git_changed_paths_sees_untracked_new_file(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "new_module.py").write_text("x = 1\n", encoding="utf-8")

    changed = _git_changed_paths(tmp_path)

    assert ("new_module.py", True) in changed


def test_git_changed_paths_excludes_deletions(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "app.py").unlink()

    changed = _git_changed_paths(tmp_path)

    assert changed == []


def test_ingest_local_diff_builds_synthetic_patch_for_untracked_file(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "new_module.py").write_text("import os\nx = 1\n", encoding="utf-8")

    settings = get_settings()
    repo_config = RepoConfig()
    budget = effective_budget(repo_config, settings)
    files, patches, dep_contents, dep_patches, exceeded = _ingest_local_diff(tmp_path, repo_config, budget)

    assert files["new_module.py"] == "import os\nx = 1\n"
    assert patches["new_module.py"] == "@@ -0,0 +1,2 @@"
    assert exceeded is False


def test_ingest_local_diff_builds_real_patch_for_tracked_modification(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "app.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")

    settings = get_settings()
    repo_config = RepoConfig()
    budget = effective_budget(repo_config, settings)
    files, patches, _dep_contents, _dep_patches, _exceeded = _ingest_local_diff(tmp_path, repo_config, budget)

    assert files["app.py"] == "def add(a, b):\n    return a - b\n"
    assert "@@ " in patches["app.py"]
    assert "-    return a + b" in patches["app.py"]
    assert "+    return a - b" in patches["app.py"]


def test_ingest_local_diff_separates_dependency_manifest(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "requirements.txt").write_text("pyyaml==5.3\n", encoding="utf-8")

    settings = get_settings()
    repo_config = RepoConfig()
    budget = effective_budget(repo_config, settings)
    files, patches, dep_contents, dep_patches, _exceeded = _ingest_local_diff(tmp_path, repo_config, budget)

    assert "requirements.txt" not in files
    assert "requirements.txt" not in patches
    assert dep_contents["requirements.txt"] == "pyyaml==5.3\n"
    assert dep_patches["requirements.txt"] == "@@ -0,0 +1,1 @@"


def test_serialize_finding_uses_severity_name_not_int():
    f = Finding.create(file="a.py", start_line=1, end_line=1, severity=Severity.HIGH, source_tool="bandit", rule_id="B105", message="x")
    d = _serialize_finding(f)
    assert d["severity"] == "HIGH"
    assert d["file"] == "a.py"


def test_serialize_dismissed():
    d = DismissedFinding(file="a.py", start_line=3, rule_id="B105", reason="test fixture")
    out = _serialize_dismissed(d)
    assert out == {"file": "a.py", "start_line": 3, "rule_id": "B105", "reason": "test fixture"}


# --- Git subprocess errors are caught, not left to crash
# the MCP tool call (found via CodeGuard's own review of PR #3, B603).

def test_git_repo_root_raises_git_error_on_a_non_git_directory(tmp_path):
    with pytest.raises(GitError, match="git .* failed"):
        _git_repo_root(str(tmp_path))


def test_git_repo_root_raises_git_error_when_git_is_not_installed(tmp_path):
    with patch("codeguard.mcp.server.subprocess.run", side_effect=FileNotFoundError()):
        with pytest.raises(GitError, match="not installed"):
            _git_repo_root(str(tmp_path))


async def test_run_review_diff_returns_a_clean_error_object_for_a_non_git_directory(tmp_path):
    result = await _run_review_diff(str(tmp_path))

    assert "error" in result
    assert result["findings"] == []
    assert result["summary"] == ""
