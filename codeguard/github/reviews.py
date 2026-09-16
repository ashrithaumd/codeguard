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
REVIEW_COMMENTS_URL = "https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/reviews/{review_id}/comments"


def post_review(
    token: str, owner: str, repo: str, pr_number: int,
    commit_id: str, body: str, comments: list[dict],
) -> int:
    """Returns the created review's id — the feedback loop needs
    it to look up each inline comment's own id afterward (see
    fetch_review_comments), since a threaded reply's `in_reply_to_id`
    only means anything once we know which comment_id maps to which
    finding's fingerprint.
    """
    payload = {"commit_id": commit_id, "body": body, "event": "COMMENT"}
    if comments:
        payload["comments"] = comments

    resp = requests.post(
        REVIEWS_URL.format(owner=owner, repo=repo, pr_number=pr_number),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json=payload, timeout=20,
    )
    resp.raise_for_status()
    return resp.json()["id"]


def fetch_review_comments(token: str, owner: str, repo: str, pr_number: int, review_id: int) -> list[dict]:
    """The comments belonging to one specific review — not
    GET /pulls/{pr}/comments, which returns every review comment ever
    posted on the PR by anyone. Each item's own `id` is the comment_id
    a later `pull_request_review_comment` reply's `in_reply_to_id` will
    reference; `body` is used to recover the fingerprint marker
    _findings_to_review_comments appended (see codeguard/pipeline/feedback.py).
    """
    resp = requests.get(
        REVIEW_COMMENTS_URL.format(owner=owner, repo=repo, pr_number=pr_number, review_id=review_id),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json()
