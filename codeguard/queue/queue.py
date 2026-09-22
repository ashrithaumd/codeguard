"""Queue primitives: enqueue, lease-based claim, heartbeat renewal, ack, nack.

Ported from Reliqueue's core/queue.py (asyncpg) to psycopg3 + psycopg_pool.
The SQL and concurrency logic are kept faithful to the original — that
part was adversarially tested there (0 double-claims across 100+
concurrent trials) and re-verified here after translation, not just
trusted. What changed is purely driver-level: $1/$2 -> %s placeholders,
asyncpg's Record -> psycopg3's dict_row, and explicit Jsonb() wrapping on
writes (psycopg3, unlike asyncpg's registered codec, needs the payload
dict wrapped explicitly on the way in; reads decode jsonb -> dict
automatically without any extra configuration — see tests/queue for the
dedicated test proving this both ways, since it's the easiest place to
get a silent bug while porting).

Concurrency model: claim_batch() uses a single atomic
"SELECT ... FOR UPDATE SKIP LOCKED" + UPDATE query, so concurrent workers
polling at the same time never contend on the same row and never
double-claim. extend_lease(), ack(), and nack() are all guarded by
"WHERE leased_by = %(worker_id)s AND status = 'leased'" — a worker that
has lost its lease (already reaped by the time it calls back in) gets a
no-op instead of corrupting a job someone else now owns.

Dead-lettering deletes the row from `jobs` and moves it to `dead_letters`
— done both here (nack() exhausting attempts) and in queue/reaper.py (an
expired lease found already at/over max_attempts, i.e. a worker that
crash-looped without ever calling nack() itself). Both paths must exist
for a crash-looping job to reliably reach the DLQ instead of cycling
leased -> pending forever.
"""

from __future__ import annotations

import random
from typing import Any
from uuid import UUID

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from codeguard.queue.models import DeadLetter, Job

DEFAULT_BASE_BACKOFF = 1.0
DEFAULT_MAX_DELAY = 60.0


def compute_backoff(attempt: int, base: float = DEFAULT_BASE_BACKOFF, max_delay: float = DEFAULT_MAX_DELAY) -> float:
    """Exponential backoff with partial jitter: base * 2**(attempt-1), capped at
    max_delay, plus up to 20% extra jitter on top.
    """
    delay = min(base * (2 ** (attempt - 1)), max_delay)
    jitter = random.uniform(0, delay * 0.2)
    return delay + jitter


async def enqueue(
    pool: AsyncConnectionPool,
    *,
    type: str,
    payload: dict[str, Any],
    idempotency_key: str,
    run_after=None,
) -> tuple[Job, bool]:
    """Insert a job. Returns (job, created) — created=False if idempotency_key already
    existed, in which case the *existing* row is returned unchanged (a no-op enqueue,
    not a duplicate). The webhook handler uses `created` to decide whether this
    delivery is new or already seen (e.g. a GitHub webhook redelivery).
    """
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO jobs (type, payload, idempotency_key, run_after)
                VALUES (%s, %s, %s, COALESCE(%s, now()))
                ON CONFLICT (idempotency_key) DO NOTHING
                RETURNING *
                """,
                (type, Jsonb(payload), idempotency_key, run_after),
            )
            row = await cur.fetchone()
            if row is not None:
                return Job.from_record(row), True

            await cur.execute("SELECT * FROM jobs WHERE idempotency_key = %s", (idempotency_key,))
            existing = await cur.fetchone()
            return Job.from_record(existing), False


async def claim_batch(
    pool: AsyncConnectionPool,
    *,
    worker_id: str,
    batch_size: int,
    lease_seconds: int,
) -> list[Job]:
    """Atomically claim up to batch_size pending, due jobs. `attempts` increments on
    every claim (every *delivery*), not only on explicit failure — this is what lets
    the reaper detect a crash-looping job by attempts alone, without ever seeing a
    nack().

    Each returned Job also carries `lease_recovery_seconds`: for a job that's being
    claimed after the reaper recovered its previously-expired lease, this is the
    elapsed time (computed in SQL, so immune to any host/DB clock drift) from that
    recovery to this claim. For an ordinary fresh claim it's None. The caller (the
    worker) is expected to feed non-None values into a Prometheus histogram — see
    worker/main.py's LEASE_RECOVERY_SECONDS.

    `AS MATERIALIZED` pins the candidate-selection CTE against Postgres 12+'s default
    CTE inlining — defensive best practice for this pattern, cheap regardless.
    """
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                WITH claimed AS MATERIALIZED (
                    SELECT id, lease_recovered_at AS prior_recovered_at
                    FROM jobs
                    WHERE status = 'pending'
                      AND run_after <= now()
                    ORDER BY created_at
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                UPDATE jobs
                SET status = 'leased',
                    leased_by = %s,
                    leased_until = now() + make_interval(secs => %s),
                    attempts = attempts + 1,
                    lease_recovered_at = NULL,
                    updated_at = now()
                FROM claimed
                WHERE jobs.id = claimed.id
                RETURNING jobs.*, EXTRACT(EPOCH FROM (now() - claimed.prior_recovered_at)) AS lease_recovery_seconds
                """,
                (batch_size, worker_id, lease_seconds),
            )
            rows = await cur.fetchall()
            return [Job.from_record(r) for r in rows]


async def extend_lease(pool: AsyncConnectionPool, *, job_id: UUID, worker_id: str, lease_seconds: int) -> bool:
    """Renew a lease (the heartbeat). Returns False if this worker no longer holds
    it — already reaped or reassigned — which the worker treats as a signal to
    abandon processing.
    """
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE jobs
                SET leased_until = now() + make_interval(secs => %s), updated_at = now()
                WHERE id = %s AND leased_by = %s AND status = 'leased'
                RETURNING id
                """,
                (lease_seconds, job_id, worker_id),
            )
            row = await cur.fetchone()
            return row is not None


async def ack(pool: AsyncConnectionPool, *, job_id: UUID, worker_id: str) -> bool:
    """Mark a job done. Guarded by leased_by so a worker that has lost its lease
    cannot ack a job it no longer owns.
    """
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE jobs
                SET status = 'done', updated_at = now()
                WHERE id = %s AND leased_by = %s AND status = 'leased'
                RETURNING id
                """,
                (job_id, worker_id),
            )
            row = await cur.fetchone()
            return row is not None


async def nack(
    pool: AsyncConnectionPool,
    *,
    job_id: UUID,
    worker_id: str,
    reason: str,
    max_attempts: int,
    base_backoff: float = DEFAULT_BASE_BACKOFF,
    max_delay: float = DEFAULT_MAX_DELAY,
    explicit_delay: float | None = None,
) -> DeadLetter | None:
    """Report a job failure. If attempts >= max_attempts, moves the row to
    dead_letters and deletes it from jobs, returning the DeadLetter — the
    caller (the worker) uses this to best-effort post a "couldn't review"
    comment, keeping this module itself GitHub-agnostic. Otherwise
    schedules a retry at now() + delay and returns None.

    `explicit_delay`, if given, is used instead of compute_backoff() —
    for a GitHub rate-limit response, the worker extracts a delay from
    Retry-After/X-RateLimit-Reset and passes it here rather than trusting
    generic exponential backoff to happen to be long enough.

    A worker that no longer holds the lease (leased_by/status mismatch)
    gets a silent no-op (returns None) — its lease was already reaped.
    """
    async with pool.connection() as conn:
        async with conn.transaction():
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    SELECT * FROM jobs
                    WHERE id = %s AND leased_by = %s AND status = 'leased'
                    FOR UPDATE
                    """,
                    (job_id, worker_id),
                )
                row = await cur.fetchone()
                if row is None:
                    return None

                if row["attempts"] >= max_attempts:
                    await cur.execute(
                        """
                        INSERT INTO dead_letters (id, type, payload, idempotency_key,
                                                   attempts, failed_reason, moved_at, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, now(), %s)
                        RETURNING *
                        """,
                        (row["id"], row["type"], Jsonb(row["payload"]), row["idempotency_key"],
                         row["attempts"], reason, row["created_at"]),
                    )
                    dl_row = await cur.fetchone()
                    await cur.execute("DELETE FROM jobs WHERE id = %s", (job_id,))
                    return DeadLetter.from_record(dl_row)

                delay = explicit_delay if explicit_delay is not None else compute_backoff(row["attempts"], base_backoff, max_delay)
                await cur.execute(
                    """
                    UPDATE jobs
                    SET status = 'pending', leased_by = NULL, leased_until = NULL,
                        run_after = now() + make_interval(secs => %s), updated_at = now()
                    WHERE id = %s
                    """,
                    (delay, job_id),
                )
                return None


async def get_job(pool: AsyncConnectionPool, job_id: UUID) -> Job | None:
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
            row = await cur.fetchone()
            return Job.from_record(row) if row else None


async def list_jobs(pool: AsyncConnectionPool, *, status: str | None = None, limit: int = 50, offset: int = 0) -> list[Job]:
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            if status is not None:
                await cur.execute(
                    "SELECT * FROM jobs WHERE status = %s ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    (status, limit, offset),
                )
            else:
                await cur.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC LIMIT %s OFFSET %s",
                    (limit, offset),
                )
            rows = await cur.fetchall()
            return [Job.from_record(r) for r in rows]


async def release(pool: AsyncConnectionPool, *, job_id: UUID, worker_id: str) -> bool:
    """Hand a leased job straight back to the queue, unchanged.

    Not a nack. A nack means "this job failed": it burns an attempt,
    applies backoff, and after enough of them dead-letters the job. A
    worker shutting down has learned nothing about the job — it simply
    is not going to be the one to finish it. Charging an attempt for a
    deploy would let a job that is redelivered across a few rollouts
    dead-letter without ever having failed.

    So: status back to 'pending', lease cleared, attempts untouched,
    run_after left alone so it is immediately claimable by the replica
    that is replacing this one. Guarded by leased_by for the same reason
    ack() is — a worker that has already lost its lease must not reach
    in and reset a job another worker now owns.
    """
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                UPDATE jobs
                SET status = 'pending', leased_by = NULL, leased_until = NULL,
                    run_after = now(), updated_at = now()
                WHERE id = %s AND leased_by = %s AND status = 'leased'
                RETURNING id
                """,
                (job_id, worker_id),
            )
            return await cur.fetchone() is not None
