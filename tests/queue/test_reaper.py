"""Closes the last carried-over gap from Phase 2's review: the reaper's
own crash-loop path (a worker that lease-expires repeatedly without ever
calling nack()) was ported from Reliqueue and trusted by structural
analogy to Reliqueue's own tested version, but never actually exercised
here. It is now.

Leases are forced into an "already expired" state via a direct SQL
UPDATE rather than by sleeping past a real lease_seconds — sleeping
would make the suite slow and reintroduce host/container clock-drift as
a source of flakiness (see tests/queue/test_queue.py's backoff test for
the same reasoning). reap_expired_leases()'s query only cares that
leased_until < now() in the database's own clock, so forcing it directly
exercises exactly the same code path a real expiry would.
"""

from __future__ import annotations

import uuid

from codeguard.queue.queue import claim_batch, enqueue
from codeguard.queue.reaper import reap_expired_leases

WORKER_A = "worker-a"
WORKER_B = "worker-b"


def key() -> str:
    return f"test-{uuid.uuid4().hex[:12]}"


async def _enqueue_one(pool):
    job, created = await enqueue(pool, type="pull_request_review", payload={}, idempotency_key=key())
    assert created
    return job


async def _force_expire(pool, job_id) -> None:
    async with pool.connection() as conn:
        await conn.execute("UPDATE jobs SET leased_until = now() - interval '1 second' WHERE id = %s", (job_id,))


async def test_expired_lease_under_max_attempts_returns_to_pending(pool):
    job = await _enqueue_one(pool)
    [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=30)
    assert claimed.attempts == 1
    await _force_expire(pool, claimed.id)

    result = await reap_expired_leases(pool, max_attempts=5)
    assert result.total == 1
    assert result.dead_lettered == []
    assert result.requeued_count == 1

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT status, leased_by, leased_until FROM jobs WHERE id = %s", (claimed.id,))
            row = await cur.fetchone()
    assert row["status"] == "pending"
    assert row["leased_by"] is None
    assert row["leased_until"] is None


async def test_expired_lease_at_max_attempts_moves_to_dead_letters(pool):
    job = await _enqueue_one(pool)
    [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=30)
    assert claimed.attempts == 1
    await _force_expire(pool, claimed.id)

    result = await reap_expired_leases(pool, max_attempts=1)
    assert result.requeued_count == 0
    assert len(result.dead_lettered) == 1
    dl = result.dead_lettered[0]
    assert dl.id == claimed.id
    assert dl.attempts == 1
    assert "lease expired" in dl.failed_reason

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT count(*) AS n FROM jobs WHERE id = %s", (claimed.id,))
            assert (await cur.fetchone())["n"] == 0


async def test_reap_ignores_leases_not_yet_expired(pool):
    job = await _enqueue_one(pool)
    [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=300)
    # deliberately NOT force-expired — leased_until is ~5 minutes out

    result = await reap_expired_leases(pool, max_attempts=1)
    assert result.total == 0

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT status, leased_by FROM jobs WHERE id = %s", (claimed.id,))
            row = await cur.fetchone()
    assert row["status"] == "leased"
    assert row["leased_by"] == WORKER_A


async def test_crash_loop_via_repeated_lease_expiry_reaches_dead_letters_without_nack(pool):
    """Simulates a worker that crashes on every single delivery of the
    same job — never once calling nack() — purely via claim + force-
    expire + reap, across multiple attempts. This is the exact bug the
    reaper's attempts check exists to prevent: without it, this job
    would cycle leased <-> pending forever and never reach dead_letters.
    """
    max_attempts = 3
    job = await _enqueue_one(pool)

    for expected_attempt in (1, 2):
        [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=30)
        assert claimed.id == job.id
        assert claimed.attempts == expected_attempt
        await _force_expire(pool, claimed.id)

        result = await reap_expired_leases(pool, max_attempts=max_attempts)
        assert result.total == 1
        assert result.dead_lettered == [], f"dead-lettered too early, at attempt {expected_attempt}"
        assert result.requeued_count == 1

    # Third delivery: attempts reaches max_attempts. Still no nack() ever
    # called — the crash loop continues, and this time the reaper alone
    # must route it to the DLQ.
    [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=30)
    assert claimed.attempts == max_attempts
    await _force_expire(pool, claimed.id)

    result = await reap_expired_leases(pool, max_attempts=max_attempts)
    assert result.requeued_count == 0
    assert len(result.dead_lettered) == 1
    assert result.dead_lettered[0].id == job.id
    assert result.dead_lettered[0].attempts == max_attempts

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT count(*) AS n FROM jobs WHERE id = %s", (job.id,))
            assert (await cur.fetchone())["n"] == 0
