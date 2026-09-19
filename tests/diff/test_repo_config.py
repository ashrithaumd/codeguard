"""Exercises the .codeguard.yml fallback paths — not just the happy
paths (missing file, valid YAML) verified live. Mocked at
get_file_content (the GitHub-fetching boundary) rather
than hitting the real API, since what's under test here is
load_repo_config's own parsing/fallback logic, not GitHub connectivity.
"""

from __future__ import annotations

from unittest.mock import patch

from codeguard.config import RepoConfig
from codeguard.github.repo_config import load_repo_config
from codeguard.severity import Severity


def test_missing_file_falls_back_to_defaults():
    with patch("codeguard.github.repo_config.get_file_content", return_value=None):
        result = load_repo_config("fake-token", "owner", "repo", "main")
    assert result == RepoConfig()


def test_malformed_yaml_falls_back_to_defaults():
    with patch("codeguard.github.repo_config.get_file_content", return_value="{unclosed: bracket"):
        result = load_repo_config("fake-token", "owner", "repo", "main")
    assert result == RepoConfig()


def test_yaml_failing_schema_validation_falls_back_to_defaults():
    # max_files_per_pr must be an int; a nested mapping can't validate.
    with patch("codeguard.github.repo_config.get_file_content", return_value="max_files_per_pr: {not: a-number}"):
        result = load_repo_config("fake-token", "owner", "repo", "main")
    assert result == RepoConfig()


def test_fetch_raising_falls_back_to_defaults():
    with patch("codeguard.github.repo_config.get_file_content", side_effect=Exception("network error")):
        result = load_repo_config("fake-token", "owner", "repo", "main")
    assert result == RepoConfig()


def test_valid_yaml_actually_parses_including_severity_string():
    yaml_content = "fix_threshold: medium\nmax_files_per_pr: 3\nignored_paths:\n  - vendor/*\n"
    with patch("codeguard.github.repo_config.get_file_content", return_value=yaml_content):
        result = load_repo_config("fake-token", "owner", "repo", "main")
    assert result.max_files_per_pr == 3
    assert result.fix_threshold == Severity.MEDIUM
    assert result.ignored_paths == ["vendor/*"]
