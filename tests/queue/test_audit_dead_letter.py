"""A dead-lettered audit must not stay 'running' forever.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
handle_repo_audit sets status='running' and is the ONLY writer that ever
sets a terminal status. If the worker dies and the job is subsequently
dead-lettered -- lease expiry past max_delivery_attempts, or nack()
exhausting them -- nothing calls finish_audit. The audit row stays
'running' permanently.

That is worse than a stuck row. `audits_one_in_flight_per_repo` is a
partial unique index over status IN ('queued','running'), so a
permanently-running row means THAT REPOSITORY CAN NEVER BE AUDITED
AGAIN. One dead worker takes a repo out of service for good.

Confirmed before the fix by grep: no writer of `audits` exists outside
handle_repo_audit, and api/main.py's _on_sweep only calls
notify_dead_letter.
"""

from __future__ import annotations

import uuid

import pytest

from codeguard.api.audits import AuditInFlight, get_audit, request_audit
from codeguard.queue.queue import claim_batch, enqueue, nack

OWNER = "acme"
REPO = "widgets"


async def _queued_audit_with_job(pool):
    """An audit mid-flight: row is 'running', job is leased, exactly as a
    worker that is about to die would leave it."""
    audit = await request_audit(
        pool, owner=OWNER, repo=REPO, requested_by="tester", private=False,
    )
    job, _ = await enqueue(
        pool, type="repo_audit",
        payload={"audit_id": str(audit["id"]), "owner": OWNER, "repo": REPO,
                 "target": f"https://github.com/{OWNER}/{REPO}"},
        idempotency_key=f"repo_audit:{audit['id']}",
    )
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE audits SET status = 'running', started_at = now() WHERE id = %s",
            (audit["id"],),
        )
    return audit, job


async def test_a_dead_lettered_audit_is_marked_failed(pool):
    """The core regression. Before the fix this row stays 'running'."""
    from codeguard.api.audits import fail_audit_for_dead_letter

    audit, job = await _queued_audit_with_job(pool)
    [claimed] = await claim_batch(pool, worker_id="w1", batch_size=1, lease_seconds=30)

    dead = await nack(
        pool, job_id=claimed.id, worker_id="w1", reason="worker died",
        max_attempts=1,
    )
    assert dead is not None, "max_attempts=1 must dead-letter on the first nack"

    await fail_audit_for_dead_letter(pool, dead)

    row = await get_audit(pool, audit["id"])
    assert row["status"] == "failed"
    assert row["error"], "a failed audit must say why"
    assert row["finished_at"] is not None


async def test_the_repo_becomes_auditable_again(pool):
    """The consequence that makes this more than cosmetic: while the row
    says 'running', the partial unique index blocks every future audit of
    that repository."""
    from codeguard.api.audits import fail_audit_for_dead_letter

    audit, job = await _queued_audit_with_job(pool)
    [claimed] = await claim_batch(pool, worker_id="w1", batch_size=1, lease_seconds=30)
    dead = await nack(pool, job_id=claimed.id, worker_id="w1",
                      reason="worker died", max_attempts=1)

    # Blocked while the corpse is still 'running'.
    with pytest.raises(AuditInFlight):
        await request_audit(pool, owner=OWNER, repo=REPO,
                           requested_by="tester", private=False)

    await fail_audit_for_dead_letter(pool, dead)

    # Auditable again.
    second = await request_audit(pool, owner=OWNER, repo=REPO,
                                 requested_by="tester", private=False)
    assert second["id"] != audit["id"]


async def test_a_terminal_audit_is_never_overwritten(pool):
    """A redelivery that dead-letters AFTER the audit already finished
    must not rewrite a 'done' row into 'failed'. The guard is a WHERE on
    the current status, not a blind UPDATE."""
    from codeguard.api.audits import fail_audit_for_dead_letter, finish_audit

    audit, job = await _queued_audit_with_job(pool)
    await finish_audit(pool, audit["id"], status="done",
                       report_markdown="# all good", exit_code=0)

    [claimed] = await claim_batch(pool, worker_id="w1", batch_size=1, lease_seconds=30)
    dead = await nack(pool, job_id=claimed.id, worker_id="w1",
                      reason="late failure", max_attempts=1)
    await fail_audit_for_dead_letter(pool, dead)

    row = await get_audit(pool, audit["id"])
    assert row["status"] == "done", "a finished audit must stay finished"
    assert row["report_markdown"] == "# all good"


async def test_a_non_audit_dead_letter_is_ignored(pool):
    """pull_request_review dead letters have no audit row. The helper must
    be a no-op for them rather than raising or guessing."""
    from codeguard.api.audits import fail_audit_for_dead_letter

    job, _ = await enqueue(
        pool, type="pull_request_review",
        payload={"owner": OWNER, "repo": REPO, "pr_number": 1},
        idempotency_key=f"pr:{uuid.uuid4()}",
    )
    [claimed] = await claim_batch(pool, worker_id="w1", batch_size=1, lease_seconds=30)
    dead = await nack(pool, job_id=claimed.id, worker_id="w1",
                      reason="boom", max_attempts=1)

    await fail_audit_for_dead_letter(pool, dead)  # must not raise


async def test_a_dead_letter_with_no_audit_id_is_ignored(pool):
    """Defensive: a repo_audit payload missing audit_id (a hand-enqueued
    job, a future payload change) must not crash the reaper's sweep."""
    from codeguard.api.audits import fail_audit_for_dead_letter

    job, _ = await enqueue(
        pool, type="repo_audit", payload={"owner": OWNER, "repo": REPO},
        idempotency_key=f"repo_audit:{uuid.uuid4()}",
    )
    [claimed] = await claim_batch(pool, worker_id="w1", batch_size=1, lease_seconds=30)
    dead = await nack(pool, job_id=claimed.id, worker_id="w1",
                      reason="boom", max_attempts=1)

    await fail_audit_for_dead_letter(pool, dead)  # must not raise


async def test_the_reaper_sweep_path_also_fails_the_audit(pool):
    """The path that does NOT go through the worker at all.

    A crash-looping worker never calls nack(); the reaper dead-letters on
    lease expiry instead, and api/main.py's _on_sweep is the only code
    that sees the result. Both producers of a DeadLetter must fail the
    audit, so both are tested.
    """
    from codeguard.api.main import _on_sweep
    from codeguard.queue.reaper import reap_expired_leases

    audit, job = await _queued_audit_with_job(pool)
    [claimed] = await claim_batch(pool, worker_id="w1", batch_size=1, lease_seconds=30)
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE jobs SET leased_until = now() - interval '1 second', attempts = 5 "
            "WHERE id = %s", (claimed.id,),
        )

    result = await reap_expired_leases(pool, max_attempts=5)
    assert len(result.dead_lettered) == 1, "the reaper should have dead-lettered it"

    await _on_sweep(pool, result)

    row = await get_audit(pool, audit["id"])
    assert row["status"] == "failed"
