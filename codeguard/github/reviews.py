"""Posts ONE PR Review — a single API call carrying every inline
comment plus the summary body, rather than N separate comment calls.
Comments may be empty (a clean-review body only) — GitHub's review API
accepts that; see codeguard/pipeline/nodes.py's summarize for why a
zero-findings review still always gets posted rather than staying
silent.
"""

from __future__ import annotations

import requests

REVIEWS_URL = "https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews"


def post_review(
    token: str, owner: str, repo: str, pr_number: int,
    commit_id: str, body: str, comments: list[dict],
) -> None:
    payload = {"commit_id": commit_id, "body": body, "event": "COMMENT"}
    if comments:
        payload["comments"] = comments

    resp = requests.post(
        REVIEWS_URL.format(owner=owner, repo=repo, pr_number=pr_number),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json=payload, timeout=20,
    )
    resp.raise_for_status()
