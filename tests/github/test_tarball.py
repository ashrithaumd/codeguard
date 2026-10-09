"""The repository's Python files at one commit, from one tarball request
(codeguard/github/tarball.py), for impact analysis.

One authenticated request instead of one per file, the token in a header
(never in a URL, never in a clone command), held in memory (nothing written
to disk), and capped: compressed bytes, per-file bytes, total bytes, file
count. Only regular .py files come out; links, devices and paths that climb
out of the tree are skipped.
"""

from __future__ import annotations

import io
import tarfile
from unittest.mock import patch

import pytest

from codeguard.github.tarball import TarballTooLarge, fetch_python_files

TOKEN = "ghs_test_token_not_real"


def _tarball(entries: dict[str, bytes], *, links: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(f"owner-repo-abc123/{name}" if not name.startswith("/") else name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(f"owner-repo-abc123/{name}")
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return buf.getvalue()


class _Resp:
    def __init__(self, body: bytes, status: int = 200):
        self.status_code = status
        self.raw = io.BytesIO(body)

    def close(self):
        pass


def _fetch(body: bytes, status: int = 200, **caps):
    with patch("codeguard.github.tarball.requests.get", return_value=_Resp(body, status)) as get:
        files = fetch_python_files(TOKEN, "owner", "repo", "a" * 40, **caps)
    return files, get


def test_only_python_files_come_out_keyed_by_repo_path():
    files, _ = _fetch(_tarball({"app/main.py": b"x = 1\n", "README.md": b"# hi", "pkg/__init__.py": b""}))
    assert files == {"app/main.py": "x = 1\n", "pkg/__init__.py": ""}


def test_one_request_with_the_token_in_a_header_and_not_in_the_url():
    _, get = _fetch(_tarball({"a.py": b"1"}))
    get.assert_called_once()
    url = get.call_args.args[0]
    assert url == f"https://api.github.com/repos/owner/repo/tarball/{'a' * 40}"
    assert TOKEN not in url
    assert get.call_args.kwargs["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert get.call_args.kwargs["stream"] is True and get.call_args.kwargs["timeout"]


def test_links_and_paths_that_climb_out_are_skipped():
    body = _tarball({"ok.py": b"1", "../evil.py": b"2", "a/../../evil2.py": b"3"},
                    links={"link.py": "/etc/passwd"})
    files, _ = _fetch(body)
    assert files == {"ok.py": "1"}


def test_an_oversized_file_is_skipped_and_the_rest_kept():
    files, _ = _fetch(_tarball({"big.py": b"x" * 2000, "small.py": b"y"}), max_file_bytes=1000)
    assert files == {"small.py": "y"}


def test_too_many_compressed_bytes_stops_the_download():
    body = _tarball({f"m{i}.py": bytes(range(256)) * 40 for i in range(50)})
    with pytest.raises(TarballTooLarge):
        _fetch(body, max_compressed_bytes=len(body) // 2)


def test_too_much_python_in_total_stops():
    with pytest.raises(TarballTooLarge):
        _fetch(_tarball({f"m{i}.py": b"x" * 600 for i in range(5)}), max_total_bytes=2000)


def test_too_many_files_stops():
    with pytest.raises(TarballTooLarge):
        _fetch(_tarball({f"m{i}.py": b"1" for i in range(20)}), max_files=10)


def test_a_failed_request_raises_without_echoing_the_token():
    with pytest.raises(RuntimeError) as exc:
        _fetch(b"", status=404)
    assert TOKEN not in str(exc.value)


def test_undecodable_bytes_are_replaced_not_fatal():
    files, _ = _fetch(_tarball({"a.py": b"s = '\xff'\n"}))
    assert files["a.py"].startswith("s = '")
