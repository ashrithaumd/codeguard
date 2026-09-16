"""Regression test for a real bug found during live verification: a
worker that successfully posts a GitHub comment and then crashes before
ack() causes a redelivery that posts the same comment again — the queue
guarantees at-least-once *delivery*, not at-most-once *side effect*.
Confirmed happening live against a real installed GitHub App (two
identical comments landed on the same PR from one kill-mid-job test) and
fixed with an idempotency guard (posted_comments, mirroring Reliqueue's
sent_emails pattern) — see codeguard/worker/main.py's
_review_already_posted / _record_review_posted (renamed when posting
moved from a single comment to a full PR Review; same guard).

This test proves the guard deterministically rather than via a real
timing race (which is inherently flaky here — the actual "post succeeded,
ack didn't happen yet" window is milliseconds wide, not something worth
faking a delay into production code to hit reliably): pre-record a
comment as already-posted, then call the real handler with a payload
carrying a deliberately invalid installation_id. If the guard didn't
skip, get_installation_token() would raise a real HTTPError against
GitHub's API. It doesn't — proving the real GitHub call was never
attempted.
"""

from __future__ import annotations

import asyncio
import uuid

from codeguard.queue.queue import enqueue
from codeguard.worker.main import handle_pull_request_review, _review_already_posted, _record_review_posted


async def test_comment_not_reposted_when_already_recorded(pool):
    job, _ = await enqueue(
        pool, type="pull_request_review",
        payload={"installation_id": 999999999, "owner": "x", "repo": "y", "pr_number": 1, "action": "opened"},
        idempotency_key=f"guard-test-{uuid.uuid4().hex[:8]}",
    )

    assert await _review_already_posted(pool, job) is False

    await _record_review_posted(pool, job)
    assert await _review_already_posted(pool, job) is True

    # Would raise requests.HTTPError (404) if the guard failed to skip
    # and this actually hit GitHub's API with a nonexistent installation.
    result = await handle_pull_request_review(job, pool, asyncio.Event())
    assert result is True
