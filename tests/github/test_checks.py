"""Regression coverage for codeguard.github.checks — mocked HTTP, same
style as tests/github/test_errors.py; no real GitHub calls.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from codeguard.github.checks import complete_check_run, start_check_run


def test_start_check_run_posts_in_progress_and_returns_id():
    mock_response = MagicMock()
    mock_response.json.return_value = {"id": 42}
    with patch("codeguard.github.checks.requests.post", return_value=mock_response) as mock_post:
        check_run_id = start_check_run("token", "owner", "repo", "sha123")

    assert check_run_id == 42
    _, kwargs = mock_post.call_args
    assert kwargs["json"]["status"] == "in_progress"
    assert kwargs["json"]["head_sha"] == "sha123"
    assert kwargs["json"]["name"] == "CodeGuard Review"


def test_complete_check_run_patches_with_conclusion_and_output():
    mock_response = MagicMock()
    with patch("codeguard.github.checks.requests.patch", return_value=mock_response) as mock_patch:
        complete_check_run("token", "owner", "repo", 42, conclusion="failure", title="t", summary="s")

    url_arg = mock_patch.call_args[0][0]
    assert "42" in url_arg
    _, kwargs = mock_patch.call_args
    assert kwargs["json"]["status"] == "completed"
    assert kwargs["json"]["conclusion"] == "failure"
    assert kwargs["json"]["output"] == {"title": "t", "summary": "s"}
