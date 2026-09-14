"""Raw GitHub API calls for diff ingestion: the PR's changed-files list
and arbitrary file content at a given ref. No parsing/filtering/budget
logic here — that's codeguard/diff/; this module only knows how to talk
to GitHub's REST API.
"""

from __future__ import annotations

import base64

import requests

PR_FILES_URL = "https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
CONTENTS_URL = "https://api.github.com/repos/{owner}/{repo}/contents/{path}"


def get_pr_files(token: str, owner: str, repo: str, pr_number: int) -> list[dict]:
    """The PR's changed files, each with path/status/additions/deletions
    and a `patch` (unified diff text, ~3 lines of context — GitHub's own
    default, not configurable via this endpoint). `patch` is absent for
    binary files or diffs GitHub considers too large; callers must
    handle that (filtered out, not an error).

    per_page=100 rather than paginating: comfortably covers any PR our
    budget ceilings would review in full (max_files_per_pr_ceiling
    defaults to 50), so a PR with more changed files than this either
    gets budget-truncated anyway or is large enough that pagination
    wouldn't change the outcome — not worth the complexity yet.
    """
    resp = requests.get(
        PR_FILES_URL.format(owner=owner, repo=repo, pr_number=pr_number),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        params={"per_page": 100},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def get_file_content(token: str, owner: str, repo: str, path: str, ref: str) -> str | None:
    """Full text content of one file at a specific ref (branch, tag, or
    SHA). Returns None on 404 (file doesn't exist at that ref — normal,
    e.g. a newly added file has no content at the base ref, or a repo
    with no .codeguard.yml) rather than raising, since "missing" is an
    expected, common outcome here, not an error.
    """
    resp = requests.get(
        CONTENTS_URL.format(owner=owner, repo=repo, path=path),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        params={"ref": ref},
        timeout=15,
    )
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    data = resp.json()
    if data.get("encoding") != "base64":
        raise ValueError(f"unexpected encoding for {path!r}: {data.get('encoding')}")
    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
