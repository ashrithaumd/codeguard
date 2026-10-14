"""get_file_raw: lockfiles over the contents API's 1 MB inline limit,
fetched raw and abandoned past a size cap."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from codeguard.github.diff import FileTooLarge, get_file_raw


def _resp(status=200, chunks=(b"",)):
    resp = MagicMock(status_code=status)
    resp.iter_content.return_value = iter(chunks)
    resp.__enter__.return_value = resp
    return resp


def test_raw_content_is_returned_and_requested_raw():
    with patch("codeguard.github.diff.requests.get", return_value=_resp(chunks=(b"lock", b"file"))) as get:
        assert get_file_raw("tok", "o", "r", "web/package-lock.json", "abc", 100) == "lockfile"
    kwargs = get.call_args.kwargs
    assert kwargs["headers"]["Accept"] == "application/vnd.github.raw"
    assert kwargs["params"] == {"ref": "abc"} and kwargs["stream"] is True


def test_missing_at_that_ref_is_none():
    with patch("codeguard.github.diff.requests.get", return_value=_resp(404)):
        assert get_file_raw("tok", "o", "r", "go.mod", "main", 100) is None


def test_over_the_cap_is_abandoned():
    with patch("codeguard.github.diff.requests.get", return_value=_resp(chunks=(b"x" * 60, b"x" * 60))):
        with pytest.raises(FileTooLarge):
            get_file_raw("tok", "o", "r", "go.mod", "main", 100)
