"""The repository's Python files at one commit, from ONE tarball request.

For impact analysis (codeguard/pipeline/impact.py), which needs every
caller in the repository, not just the PR's files. The alternatives were
worse: one contents-API call per file is thousands of requests on a real
repository, and a clone puts the installation token into a URL, which is
why private audits are refused today (routes/dashboard.py,
PRIVATE_AUDIT_NOTE).

  * The token goes in the Authorization header of a request to
    api.github.com. GitHub answers with a redirect to a short-lived
    codeload URL; requests drops the Authorization header when a redirect
    changes host, so the token is never sent anywhere else, and it is never
    in a URL, a log line or an error message.
  * Streamed and held in memory. Nothing is written to disk, so nothing in
    the archive can be placed anywhere.
  * Capped four ways -- compressed bytes read, bytes per file, total bytes,
    file count -- and TarballTooLarge when a cap is hit, so the caller can
    skip impact analysis with a note rather than review a partial picture.
  * Only regular files ending .py. Links, devices and any path that is
    absolute or contains `..` are skipped.
"""

from __future__ import annotations

import io
import logging
import tarfile

import requests

logger = logging.getLogger(__name__)

_API = "https://api.github.com"
_TIMEOUT = (10, 60)

MAX_COMPRESSED_BYTES = 50 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 40 * 1024 * 1024
MAX_FILES = 5000


class TarballTooLarge(Exception):
    pass


class _CappedReader(io.RawIOBase):
    """Reads through to `raw`, raising once more than `cap` bytes came back."""

    def __init__(self, raw, cap: int):
        self._raw, self._cap, self._read = raw, cap, 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        data = self._raw.read(len(buffer))
        self._read += len(data)
        if self._read > self._cap:
            raise TarballTooLarge(f"tarball exceeds {self._cap} compressed bytes")
        buffer[: len(data)] = data
        return len(data)


def _repo_path(member_name: str) -> str | None:
    """'owner-repo-sha/app/main.py' -> 'app/main.py', or None if unsafe."""
    if member_name.startswith("/"):
        return None
    _, _, rest = member_name.partition("/")
    parts = rest.split("/")
    if not rest or any(p in ("", ".", "..") for p in parts):
        return None
    return rest


def fetch_python_files(
    token: str, owner: str, repo: str, ref: str, *,
    max_compressed_bytes: int = MAX_COMPRESSED_BYTES, max_file_bytes: int = MAX_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES, max_files: int = MAX_FILES,
) -> dict[str, str]:
    """{repo path: source} for every .py file at `ref`."""
    resp = requests.get(
        f"{_API}/repos/{owner}/{repo}/tarball/{ref}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        stream=True, timeout=_TIMEOUT,
    )
    try:
        if resp.status_code != 200:
            raise RuntimeError(f"tarball request for {owner}/{repo} returned {resp.status_code}")
        if hasattr(resp.raw, "decode_content"):
            resp.raw.decode_content = False  # gzip is tarfile's job
        stream = io.BufferedReader(_CappedReader(resp.raw, max_compressed_bytes))
        files: dict[str, str] = {}
        total = 0
        with tarfile.open(fileobj=stream, mode="r|gz") as archive:
            for member in archive:
                if not member.isfile() or not member.name.endswith(".py"):
                    continue
                path = _repo_path(member.name)
                if path is None or member.size > max_file_bytes:
                    continue
                if len(files) >= max_files:
                    raise TarballTooLarge(f"more than {max_files} Python files")
                total += member.size
                if total > max_total_bytes:
                    raise TarballTooLarge(f"more than {max_total_bytes} bytes of Python")
                handle = archive.extractfile(member)
                if handle is not None:
                    files[path] = handle.read().decode("utf-8", errors="replace")
        return files
    finally:
        resp.close()
