"""The worker re-checks the PR-reviews switch before doing anything.

The webhook is the main gate (no job is queued for a repo that is OFF).
This covers the window between the two: a job queued while the switch was
ON, then the switch turned OFF before a worker claimed it. The job is acked
with no GitHub token minted, no check run, and no model call.
"""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import patch

import pytest

from codeguard.api import repo_settings
from codeguard.queue.queue import enqueue
from codeguard.worker.main import handle_pull_request_review


class _ReachedGitHub(Exception):
    pass


async def _job(pool, repo):
    job, _ = await enqueue(
        pool, type="pull_request_review",
        payload={"installation_id": 999999999, "owner": "recheck-owner", "repo": repo,
                 "pr_number": 3, "action": "opened", "head_sha": "c" * 40, "base_ref": "main"},
        idempotency_key=f"recheck-{uuid.uuid4().hex[:8]}",
    )
    return job


async def test_a_job_for_a_repo_switched_off_is_acked_without_any_github_or_model_call(pool):
    repo = f"off-{uuid.uuid4().hex[:6]}"
    await repo_settings.set_pr_reviews(pool, "recheck-owner", repo, enabled=True, updated_by="op")
    job = await _job(pool, repo)
    await repo_settings.set_pr_reviews(pool, "recheck-owner", repo, enabled=False, updated_by="op")

    with patch("codeguard.worker.main.get_installation_token", side_effect=_ReachedGitHub):
        assert await handle_pull_request_review(job, pool, asyncio.Event()) is True


async def test_a_job_for_a_repo_switched_on_goes_on_to_review(pool):
    repo = f"on-{uuid.uuid4().hex[:6]}"
    await repo_settings.set_pr_reviews(pool, "recheck-owner", repo, enabled=True, updated_by="op")
    job = await _job(pool, repo)

    # Getting as far as minting a token is the proof it passed the check.
    with patch("codeguard.worker.main.get_installation_token", side_effect=_ReachedGitHub):
        with pytest.raises(_ReachedGitHub):
            await handle_pull_request_review(job, pool, asyncio.Event())
