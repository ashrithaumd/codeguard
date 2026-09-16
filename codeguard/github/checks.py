"""One GitHub Check Run per PR review, separate from the
inline-comments-plus-summary PR Review post.py already does. A Check
Run is what shows up as a required-status-check gate in GitHub's PR
merge UI — repos that want CodeGuard to actually block a merge on
severe findings turn this into a required check in their branch
protection rules; the PR Review comments alone have no merge-gating
effect no matter how they're configured.

Needs the App's `checks: write` permission — see README's App
installation section. Every call here is wrapped by the caller
(worker/main.py) in a try/except: a missing permission or a transient
API failure degrades to "no check run posted" for this PR, never a
failed review. The PR Review (comments + summary) is the actual
review content and always gets attempted regardless of whether the
Check Run succeeds.
"""

from __future__ import annotations

import requests

CHECK_RUNS_URL = "https://api.github.com/repos/{owner}/{repo}/check-runs"
CHECK_RUN_URL = "https://api.github.com/repos/{owner}/{repo}/check-runs/{check_run_id}"
CHECK_NAME = "CodeGuard Review"


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}


def start_check_run(token: str, owner: str, repo: str, head_sha: str) -> int:
    """Posted as early as possible in the job — before the (potentially
    100+ second) review graph even runs — purely so the PR shows
    "CodeGuard Review — in progress" instead of nothing at all while a
    webhook-triggered review is in flight. Returns the check run id
    complete_check_run() needs to finish it.
    """
    resp = requests.post(
        CHECK_RUNS_URL.format(owner=owner, repo=repo),
        headers=_headers(token),
        json={"name": CHECK_NAME, "head_sha": head_sha, "status": "in_progress"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["id"]


def complete_check_run(
    token: str, owner: str, repo: str, check_run_id: int, *, conclusion: str, title: str, summary: str,
) -> None:
    """conclusion is GitHub's own enum: "success" | "failure" | "neutral"
    (also accepts a few others this pipeline never produces). See
    worker/main.py's own `_check_run_conclusion` for how that's derived
    from max confirmed severity vs repo_config.gate_threshold.
    """
    resp = requests.patch(
        CHECK_RUN_URL.format(owner=owner, repo=repo, check_run_id=check_run_id),
        headers=_headers(token),
        json={
            "status": "completed",
            "conclusion": conclusion,
            "output": {"title": title, "summary": summary},
        },
        timeout=15,
    )
    resp.raise_for_status()
