"""Sweeps jobs whose lease expired without a heartbeat (worker crashed, was killed,
network partitioned, etc.). This is what makes worker crashes recoverable: a job is
never stuck 'leased' forever just because the worker that owned it died.

Correctness requirement: a crashed worker never calls nack(), so this function —
not just nack() — must be the thing that ultimately routes a crash-looping job to
the DLQ. If expired leases were unconditionally returned to pending, a job whose
worker keeps crashing on every delivery would cycle leased -> pending -> leased ->
pending forever and never reach dead_letters. reap_expired_leases() checks attempts
against max_attempts itself, exactly like nack() does, so both paths to the DLQ are
covered.

Placement: run as a background asyncio task inside the API process (see
codeguard/api/main.py's lifespan) — NOT inside the worker service, which is what
gets `--scale worker=N`'d. Running the reaper in N replicas would risk sweeps
racing each other; FOR UPDATE SKIP LOCKED would still protect correctness even if
that happened, but there's no reason to invite it. TODO: the api service
must stay single-replica in Azure Container Apps for this assumption to hold —
if api ever needs to scale horizontally, the reaper needs to move to a dedicated
single-instance process first.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Awaitable, Callable

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from codeguard.queue.models import DeadLetter, ReapResult

logger = logging.getLogger("codeguard.queue.reaper")

# A tick whose query time or whose gap since the previous tick exceeds this many
# multiples of the configured interval is logged at INFO even when it swept
# nothing — see run_forever's docstring. 5x rather than 2x because the loop is not
# a scheduler: asyncio.sleep(interval) is the gap BETWEEN ticks, so `since_prev`
# is always interval + the previous tick's own work, and event-loop scheduling
# jitter under load pushes that around. 2x would cry wolf on a busy but healthy
# api process; 5x on a 1s interval means a 5-second stall, which is never normal.
_STALL_FACTOR = 5.0

# Floor under the above, because interval_seconds is a config field and nothing
# stops it being 0 — a caller wanting the tightest possible loop. A pure multiple
# would make the threshold 0 there, every tick "slower than zero", and the whole
# demotion would silently undo itself into INFO-per-tick: exactly the behaviour
# being removed, in the configuration that can least afford it. Caught by
# tests/queue/test_reaper_logging.py, which drives the loop at interval 0.
_MIN_STALL_SECONDS = 1.0


def _stall_threshold(interval_seconds: float) -> float:
    return max(_STALL_FACTOR * interval_seconds, _MIN_STALL_SECONDS)


async def reap_expired_leases(pool: AsyncConnectionPool, *, max_attempts: int) -> ReapResult:
    """One reaper pass over every 'leased' job whose lease has expired.

    - attempts >= max_attempts: move to dead_letters, delete from jobs.
    - attempts <  max_attempts: return to pending for another worker to claim.
    """
    async with pool.connection() as conn:
        async with conn.transaction():
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    WITH expired_exhausted AS (
                        SELECT * FROM jobs
                        WHERE status = 'leased' AND leased_until < now() AND attempts >= %s
                        FOR UPDATE SKIP LOCKED
                    )
                    SELECT * FROM expired_exhausted
                    """,
                    (max_attempts,),
                )
                exhausted_rows = await cur.fetchall()

                dead_lettered: list[DeadLetter] = []
                for row in exhausted_rows:
                    await cur.execute(
                        """
                        INSERT INTO dead_letters (id, type, payload, idempotency_key, attempts,
                                                   failed_reason, moved_at, created_at)
                        VALUES (%s, %s, %s, %s, %s, %s, now(), %s)
                        RETURNING *
                        """,
                        (row["id"], row["type"], Jsonb(row["payload"]), row["idempotency_key"],
                         row["attempts"], "lease expired after max delivery attempts", row["created_at"]),
                    )
                    dl_row = await cur.fetchone()
                    dead_lettered.append(DeadLetter.from_record(dl_row))

                if exhausted_rows:
                    await cur.execute(
                        "DELETE FROM jobs WHERE id = ANY(%s::uuid[])",
                        ([r["id"] for r in exhausted_rows],),
                    )
                    for dl in dead_lettered:
                        logger.warning("dead-lettered job %s: lease expired at/over max_attempts", dl.id)

                await cur.execute(
                    """
                    WITH expired_recoverable AS (
                        SELECT id FROM jobs
                        WHERE status = 'leased' AND leased_until < now() AND attempts < %s
                        FOR UPDATE SKIP LOCKED
                    )
                    UPDATE jobs
                    SET status = 'pending', leased_by = NULL, leased_until = NULL,
                        lease_recovered_at = now(), updated_at = now()
                    WHERE id IN (SELECT id FROM expired_recoverable)
                    RETURNING id
                    """,
                    (max_attempts,),
                )
                requeued_rows = await cur.fetchall()
                for r in requeued_rows:
                    logger.info("requeued job %s after lease expiry", r["id"])

    return ReapResult(dead_lettered=dead_lettered, requeued_count=len(requeued_rows))


async def run_forever(
    pool: AsyncConnectionPool,
    *,
    interval_seconds: float,
    max_attempts: int,
    on_sweep: Callable[[ReapResult], Awaitable[None] | None] | None = None,
) -> None:
    """Loop reap_expired_leases() every interval_seconds until cancelled. `on_sweep`
    is called after each pass with the ReapResult, e.g. to drive Prometheus counters
    and to best-effort post a "couldn't review" comment for each dead-lettered job
    (that GitHub-specific behavior lives in the caller, not here — this module stays
    domain-agnostic).

    Every tick logs both the wall-clock gap since the previous tick and how long
    reap_expired_leases() itself took. A long `since_prev` with a short `took` means
    the *loop* stalled; a long `took` means the *query* stalled — indistinguishable
    after the fact without this, per the incident this pattern is ported from (see
    Reliqueue's history).

    The LEVEL is chosen per tick, which is the whole trick. This used to be INFO
    unconditionally; at the 1s interval that is ~86,000 lines a day, and in
    production every one of them said "swept 0 row(s)" because an idle queue is the
    normal state. Real signal — a dead-letter, a requeue — arrived in a haystack it
    paid to store. So:

      - swept something  -> INFO. This is the event anyone greps for.
      - stalled          -> INFO. A tick that took, or waited, far longer than the
                            configured interval is itself the diagnosis the
                            paragraph above exists to enable, so it must survive at
                            the level production actually runs at.
      - quiet and prompt -> DEBUG. The overwhelming majority. Still emitted, still
                            carrying since_prev and took, just not stored by default.

    Note the interval is deliberately untouched: sweeping every second is correct and
    cheap (one indexed UPDATE against an empty set). It was never the sweeping that
    was expensive, only the narrating.
    """
    tick = 0
    prev_tick_at = time.monotonic()
    while True:
        tick += 1
        now = time.monotonic()
        since_prev = now - prev_tick_at
        prev_tick_at = now
        start = time.monotonic()
        try:
            result = await reap_expired_leases(pool, max_attempts=max_attempts)
            took = time.monotonic() - start
            # tick 1's since_prev is measured from loop entry, not from a previous
            # tick, so it is meaninglessly small — excluded rather than special-cased
            # into a false "stall".
            stalled = tick > 1 and max(took, since_prev) > _stall_threshold(interval_seconds)
            level = logging.INFO if (result.total or stalled) else logging.DEBUG
            logger.log(level,
                       "reaper tick %d: swept %d row(s) (%d dead-lettered, %d requeued), took %.3fs, %.3fs since previous tick%s",
                       tick, result.total, len(result.dead_lettered), result.requeued_count, took, since_prev,
                       " [SLOW]" if stalled else "")
            if on_sweep is not None:
                maybe_awaitable = on_sweep(result)
                if maybe_awaitable is not None:
                    await maybe_awaitable
        except asyncio.CancelledError:
            raise
        except Exception:
            took = time.monotonic() - start
            logger.exception("reaper tick %d failed after %.3fs (%.3fs since previous tick)",
                              tick, took, since_prev)
        await asyncio.sleep(interval_seconds)
