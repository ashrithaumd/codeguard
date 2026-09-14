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
TREE_URL = "https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}"


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


def get_repo_tree(token: str, owner: str, repo: str, ref: str) -> list[dict]:
    """Full recursive file listing (path + type) at `ref` — no content,
    one call regardless of repo size. Used by Phase 6's eval-hygiene
    checks to enumerate the base tree; `ref` must be the PR's base
    branch for the same reason load_repo_config's base_ref must be
    (repo_config.py) — repo-level checks describe the target repo's own
    practices, not whatever an untrusted PR head wants them to look
    like. GitHub marks very large trees `truncated: true` rather than
    erroring; not handled specially here since the caller's own file
    cap already bounds how much of this gets acted on regardless.
    """
    resp = requests.get(
        TREE_URL.format(owner=owner, repo=repo, ref=ref),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        params={"recursive": "1"},
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    return [e for e in data.get("tree", []) if e.get("type") == "blob"]
