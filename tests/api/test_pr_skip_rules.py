"""Which pull_request deliveries become a review (should_review).

In order, the first that applies decides:

  repo switch OFF              skip  (pr_reviews_off)
  label "codeguard:skip"       skip  (skip_label)
  draft                        skip  (draft), pushes to a draft included
  head already reviewed or     skip  (already_reviewed)
    queued for review
  opened / synchronize /       review the current head
    ready_for_review /
    unlabeled codeguard:skip
  anything else                ignored, as before

Removing the skip label and marking a draft ready both review the head as
it stands, once: flipping a PR draft -> ready -> draft -> ready, or the
label off and on and off, does not pay for the same head twice.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid

import pytest

from codeguard.api import repo_settings
from codeguard.config import Settings, get_settings
from codeguard.queue.queue import enqueue
from tests.api.conftest import insert_review

OWNER = "ashrithaumd"
REPO = "reliqueue"
SECRET = "skip-rules-secret"
HEAD = "e" * 40


@pytest.fixture
def signed_webhooks(monkeypatch):
    base = get_settings().model_dump()
    base["github_webhook_secret"] = SECRET
    monkeypatch.setattr("codeguard.api.routes.webhooks.get_settings", lambda: Settings(**base))


@pytest.fixture
async def switched_on(pool):
    await repo_settings.set_pr_reviews(pool, OWNER, REPO, enabled=True, updated_by="op")


def _payload(action="opened", *, draft=False, labels=(), label=None, head=HEAD, number=12):
    p = {
        "action": action, "number": number,
        "installation": {"id": 4934663},
        "repository": {"name": REPO, "owner": {"login": OWNER}, "private": False},
        "pull_request": {"title": "t", "head": {"sha": head}, "base": {"ref": "main"},
                         "draft": draft, "labels": [{"name": n} for n in labels]},
    }
    if label is not None:
        p["label"] = {"name": label}
    return p


def _deliver(client, payload):
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return client.post("/webhook", content=body, headers={
        "X-GitHub-Event": "pull_request", "X-GitHub-Delivery": uuid.uuid4().hex,
        "X-Hub-Signature-256": sig, "Content-Type": "application/json",
    }).json()


async def _jobs(pool) -> int:
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM jobs WHERE type = 'pull_request_review'")
        return (await cur.fetchone())["count"]


# --------------------------------------------------------------------------
# The label
# --------------------------------------------------------------------------

async def test_a_pr_labelled_codeguard_skip_is_not_reviewed(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload(labels=["bug", "codeguard:skip"])) == {
        "status": "skipped", "reason": "skip_label"}
    assert await _jobs(pool) == 0


async def test_the_label_matches_case_insensitively(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload(labels=["CodeGuard:Skip"]))["reason"] == "skip_label"


async def test_pushes_to_a_labelled_pr_are_skipped_too(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload("synchronize", labels=["codeguard:skip"]))["reason"] == "skip_label"
    assert await _jobs(pool) == 0


async def test_adding_the_label_queues_nothing(client, pool, signed_webhooks, switched_on):
    resp = _deliver(client, _payload("labeled", labels=["codeguard:skip"], label="codeguard:skip"))
    assert resp["status"] == "skipped"
    assert await _jobs(pool) == 0


async def test_removing_the_label_reviews_the_current_head(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload("unlabeled", labels=[], label="codeguard:skip")) == {"status": "ok"}
    assert await _jobs(pool) == 1


async def test_removing_some_other_label_does_nothing(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload("unlabeled", labels=[], label="bug"))["status"] == "ignored"
    assert await _jobs(pool) == 0


async def test_removing_the_label_from_a_draft_still_waits_for_ready(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload("unlabeled", draft=True, label="codeguard:skip"))["reason"] == "draft"
    assert await _jobs(pool) == 0


# --------------------------------------------------------------------------
# Drafts
# --------------------------------------------------------------------------

async def test_a_draft_is_not_reviewed_when_opened_or_pushed(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload("opened", draft=True)) == {"status": "skipped", "reason": "draft"}
    assert _deliver(client, _payload("synchronize", draft=True, head="f" * 40))["reason"] == "draft"
    assert await _jobs(pool) == 0


async def test_marking_a_draft_ready_reviews_it(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload("ready_for_review")) == {"status": "ok"}
    assert await _jobs(pool) == 1


async def test_a_labelled_draft_marked_ready_is_still_skipped(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload("ready_for_review", labels=["codeguard:skip"]))["reason"] == "skip_label"


# --------------------------------------------------------------------------
# The same head is not reviewed twice
# --------------------------------------------------------------------------

async def test_ready_again_for_a_head_already_reviewed_is_skipped(client, pool, signed_webhooks, switched_on):
    await insert_review(pool, owner=OWNER, repo=REPO, pr_number=12, head_sha=HEAD, pr_title="real")
    assert _deliver(client, _payload("ready_for_review")) == {
        "status": "skipped", "reason": "already_reviewed"}
    assert await _jobs(pool) == 0


async def test_draft_ready_draft_ready_queues_the_head_once(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload("ready_for_review"))["status"] == "ok"
    assert _deliver(client, _payload("converted_to_draft", draft=True))["status"] in ("ignored", "skipped")
    assert _deliver(client, _payload("ready_for_review"))["reason"] == "already_reviewed"
    assert await _jobs(pool) == 1


async def test_label_off_on_off_queues_the_head_once(client, pool, signed_webhooks, switched_on):
    assert _deliver(client, _payload("unlabeled", label="codeguard:skip"))["status"] == "ok"
    _deliver(client, _payload("labeled", labels=["codeguard:skip"], label="codeguard:skip"))
    assert _deliver(client, _payload("unlabeled", label="codeguard:skip"))["reason"] == "already_reviewed"
    assert await _jobs(pool) == 1


async def test_a_new_head_is_reviewed_even_after_the_old_one_was(client, pool, signed_webhooks, switched_on):
    await insert_review(pool, owner=OWNER, repo=REPO, pr_number=12, head_sha=HEAD, pr_title="real")
    assert _deliver(client, _payload("synchronize", head="1" * 40)) == {"status": "ok"}


async def test_a_finished_job_that_produced_no_review_does_not_count(client, pool, signed_webhooks, switched_on):
    """The worker marks a job it skipped (switch turned off mid-queue) as
    done without writing a review. That head was never reviewed, so
    removing the label later must still review it."""
    job, _ = await enqueue(pool, type="pull_request_review", idempotency_key=uuid.uuid4().hex, payload={
        "owner": OWNER, "repo": REPO, "pr_number": 12, "head_sha": HEAD})
    async with pool.connection() as conn:
        await conn.execute("UPDATE jobs SET status = 'done' WHERE id = %s", (job.id,))
    assert _deliver(client, _payload("unlabeled", label="codeguard:skip")) == {"status": "ok"}


# --------------------------------------------------------------------------
# Precedence
# --------------------------------------------------------------------------

async def test_the_repo_switch_is_checked_first(client, pool, signed_webhooks):
    assert _deliver(client, _payload(draft=True, labels=["codeguard:skip"]))["reason"] == "pr_reviews_off"
