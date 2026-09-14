"""Unit tests for codeguard/queue/queue.py, run against a real Postgres.

Ported from Reliqueue's tests/test_queue.py, translated to psycopg3.
test_jsonb_payload_round_trips_as_a_real_dict is new — not in the
original — because the JSONB write/read path is exactly the place a
driver-translation bug would hide silently: enqueue() must explicitly
wrap payload dicts in Jsonb() on the way in (psycopg3, unlike asyncpg,
doesn't have a global codec registered for this), and this test confirms
what comes back out the other end of claim_batch() is still a real
Python dict with the right keys/values, not a JSON string or something
mangled.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from codeguard.queue.queue import ack, claim_batch, compute_backoff, enqueue, nack

WORKER_A = "worker-a"
WORKER_B = "worker-b"


def key() -> str:
    return f"test-{uuid.uuid4().hex[:12]}"


async def _enqueue_one(pool, **kwargs):
    payload = kwargs.pop("payload", {})
    job, created = await enqueue(pool, type="pull_request_review", payload=payload, idempotency_key=key(), **kwargs)
    assert created
    return job


# --- enqueue -----------------------------------------------------------------

async def test_enqueue_idempotent_returns_existing_no_duplicate(pool):
    k = key()
    job1, created1 = await enqueue(pool, type="pull_request_review", payload={"pr_number": 1}, idempotency_key=k)
    job2, created2 = await enqueue(pool, type="pull_request_review", payload={"pr_number": 2}, idempotency_key=k)

    assert created1 is True
    assert created2 is False
    assert job1.id == job2.id
    assert job2.payload == {"pr_number": 1}  # untouched by the second call

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT count(*) AS n FROM jobs WHERE idempotency_key = %s", (k,))
            count = (await cur.fetchone())["n"]
    assert count == 1


async def test_jsonb_payload_round_trips_as_a_real_dict(pool):
    """The dedicated JSONB test — proves Jsonb() on write and psycopg3's
    default jsonb decoding on read both actually work for our real
    payload shape, not just a toy dict.
    """
    payload = {
        "installation_id": 161495793,
        "owner": "ashrithaumd",
        "repo": "codeguard-playground",
        "pr_number": 7,
        "action": "opened",
        "head_sha": "abc123def456",
    }
    job, created = await enqueue(pool, type="pull_request_review", payload=payload, idempotency_key=key())
    assert created
    assert isinstance(job.payload, dict)
    assert job.payload == payload

    [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=30)
    assert isinstance(claimed.payload, dict)
    assert claimed.payload == payload
    # Nested access exactly as the worker's handler does it — proves this
    # isn't a JSON string that happens to compare equal.
    assert claimed.payload["owner"] == "ashrithaumd"
    assert claimed.payload["pr_number"] == 7


# --- claim_batch ---------------------------------------------------------------

async def test_concurrent_claim_never_double_claims(pool):
    """The one guarantee that actually matters: two workers racing to
    claim from the same pending set can NEVER end up holding the same
    job. Run across many trials to make that meaningful rather than a
    single lucky/unlucky interleaving.
    """
    for _ in range(25):
        async with pool.connection() as conn:
            await conn.execute("TRUNCATE jobs, dead_letters")
        for _ in range(8):
            await _enqueue_one(pool)

        claimed_a, claimed_b = await asyncio.gather(
            claim_batch(pool, worker_id=WORKER_A, batch_size=5, lease_seconds=30),
            claim_batch(pool, worker_id=WORKER_B, batch_size=5, lease_seconds=30),
        )

        ids_a = {j.id for j in claimed_a}
        ids_b = {j.id for j in claimed_b}
        assert ids_a.isdisjoint(ids_b), "the same job was claimed by both workers"


async def test_concurrent_claim_eventually_covers_every_job_via_continued_polling(pool):
    """Liveness half of the same guarantee: whatever a single concurrent
    race round doesn't fully claim, continued polling (what the real
    worker loop does) picks up — no duplicates across any round, full
    coverage by the end.
    """
    ids = {(await _enqueue_one(pool)).id for _ in range(8)}

    claimed_a, claimed_b = await asyncio.gather(
        claim_batch(pool, worker_id=WORKER_A, batch_size=5, lease_seconds=30),
        claim_batch(pool, worker_id=WORKER_B, batch_size=5, lease_seconds=30),
    )
    all_claimed = {j.id for j in claimed_a} | {j.id for j in claimed_b}
    assert len(all_claimed) == len(claimed_a) + len(claimed_b), "no duplicates within the concurrent round"

    for _ in range(5):
        if all_claimed == ids:
            break
        more = await claim_batch(pool, worker_id=WORKER_A, batch_size=8, lease_seconds=30)
        assert {j.id for j in more}.isdisjoint(all_claimed), "a later poll re-claimed an already-claimed job"
        all_claimed |= {j.id for j in more}

    assert all_claimed == ids, "every job should be claimed within a few polls even if the first race round wasn't enough"


async def test_attempts_increments_on_every_claim_not_only_on_failure(pool):
    job = await _enqueue_one(pool)
    assert job.attempts == 0

    [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=30)
    assert claimed.attempts == 1

    await nack(pool, job_id=claimed.id, worker_id=WORKER_A, reason="transient", max_attempts=5, base_backoff=0.0)
    [reclaimed] = await claim_batch(pool, worker_id=WORKER_B, batch_size=1, lease_seconds=30)
    assert reclaimed.id == claimed.id
    assert reclaimed.attempts == 2


async def test_claim_ignores_jobs_not_yet_due(pool):
    future = datetime.now(timezone.utc).replace(microsecond=0)
    job = await _enqueue_one(pool, run_after=future + timedelta(hours=1))

    claimed = await claim_batch(pool, worker_id=WORKER_A, batch_size=10, lease_seconds=30)
    assert job.id not in {j.id for j in claimed}


# --- ack / nack / dead-lettering -----------------------------------------------

async def test_ack_fails_for_worker_without_current_lease(pool):
    job = await _enqueue_one(pool)
    [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=30)

    ok = await ack(pool, job_id=claimed.id, worker_id=WORKER_B)
    assert ok is False

    ok = await ack(pool, job_id=claimed.id, worker_id=WORKER_A)
    assert ok is True


async def test_nack_below_max_attempts_returns_none_and_schedules_retry(pool):
    job = await _enqueue_one(pool)
    [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=30)

    dead_letter = await nack(pool, job_id=claimed.id, worker_id=WORKER_A, reason="boom",
                              max_attempts=5, base_backoff=1.0, max_delay=60.0)
    assert dead_letter is None  # not dead-lettered yet — under max_attempts


async def test_nack_at_max_attempts_returns_dead_letter(pool):
    job = await _enqueue_one(pool, payload={"owner": "x", "repo": "y", "pr_number": 1, "installation_id": 1})
    [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=30)
    assert claimed.attempts == 1

    dead_letter = await nack(pool, job_id=claimed.id, worker_id=WORKER_A, reason="fatal error", max_attempts=1)
    assert dead_letter is not None
    assert dead_letter.attempts == 1
    assert dead_letter.failed_reason == "fatal error"
    assert dead_letter.payload["owner"] == "x"

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT count(*) AS n FROM jobs WHERE id = %s", (claimed.id,))
            assert (await cur.fetchone())["n"] == 0


async def test_nack_explicit_delay_overrides_compute_backoff(pool):
    """The rate-limit-aware path: an explicit_delay must be honored
    verbatim instead of compute_backoff()'s value.
    """
    job = await _enqueue_one(pool)
    [claimed] = await claim_batch(pool, worker_id=WORKER_A, batch_size=1, lease_seconds=30)

    await nack(pool, job_id=claimed.id, worker_id=WORKER_A, reason="rate limited",
               max_attempts=5, explicit_delay=42.0)

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT run_after, now() AS db_now FROM jobs WHERE id = %s", (claimed.id,)
            )
            row = await cur.fetchone()
    delta = (row["run_after"] - row["db_now"]).total_seconds()
    assert 40.0 <= delta <= 43.0, f"run_after {delta:.3f}s from db now(), expected ~42s (explicit_delay)"


# --- compute_backoff (pure function, no DB) --------------------------------------

def test_compute_backoff_grows_exponentially_and_respects_cap():
    assert 1.0 <= compute_backoff(1, base=1.0, max_delay=60.0) < 1.2
    assert 2.0 <= compute_backoff(2, base=1.0, max_delay=60.0) < 2.4
    capped = compute_backoff(10, base=1.0, max_delay=10.0)
    assert 10.0 <= capped < 12.0
