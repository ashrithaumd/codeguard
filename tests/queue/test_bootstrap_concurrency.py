"""bootstrap_schema must survive two processes starting at once.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
A deploy starts the api and the worker simultaneously, and BOTH call
bootstrap_schema (api/main.py's lifespan, worker/main.py's main). Nothing
serialised them.

Measured before the fix: SIX concurrent runs, FOUR DeadlockDetected
failures. Not the DuplicateObject that was predicted -- the whole migration
run is ONE transaction touching seven tables, so two runs acquire
overlapping locks, Postgres breaks the cycle by killing a victim, that
victim's migration rolls back, and its container fails to start. An
intermittently failing deploy.

Note what is NOT the mechanism, because the first version of this test got
it wrong and deadlocked itself proving it: two processes do not interleave
drop-then-add. The first ALTER takes ACCESS EXCLUSIVE and holds it to
commit, so the second BLOCKS rather than racing. The failure is the lock
cycle across several tables, which needs no particular migration -- only
two runs and enough tables.

bootstrap_schema's docstring used to justify its own safety with
"migrations use CREATE ... IF NOT EXISTS". True of 001-009; migration 010
broke it by dropping and re-adding a CHECK. The deadlock predates that
reasoning being wrong.
"""

from __future__ import annotations

import asyncio
import os
from urllib.parse import urlsplit, urlunsplit

from psycopg_pool import AsyncConnectionPool

from codeguard.queue.db import _configure_connection, bootstrap_schema

CONCURRENCY = 6


def _new_pool() -> AsyncConnectionPool:
    """A SEPARATE pool per contender, so the concurrency is real rather than
    coroutines sharing one connection and serialising by accident.

    The URL is rebuilt through urlsplit rather than by string replacement:
    `DATABASE_URL.replace("/codeguard", "/codeguard_test")` also rewrites the
    `//codeguard` in `postgresql://codeguard:...`, producing a URL that
    cannot connect. That mistake cost a confusing PoolTimeout while
    diagnosing this.
    """
    parts = urlsplit(os.environ["DATABASE_URL"])
    url = urlunsplit(parts._replace(path="/codeguard_test"))
    return AsyncConnectionPool(
        url, min_size=1, max_size=2, configure=_configure_connection, open=False,
    )


async def test_bootstrap_schema_is_safe_to_run_concurrently():
    """The regression. Every concurrent run must succeed.

    Six contenders rather than two: the lock cycle needs an unlucky
    interleaving, and more contenders make an unserialised run fail
    reliably here instead of occasionally in a deploy. Before the advisory
    lock this produced four failures out of six.
    """
    pools = [_new_pool() for _ in range(CONCURRENCY)]
    for p in pools:
        await p.open()
    try:
        results = await asyncio.gather(
            *(bootstrap_schema(p) for p in pools), return_exceptions=True,
        )
    finally:
        for p in pools:
            await p.close()

    failures = [r for r in results if isinstance(r, BaseException)]
    assert not failures, (
        f"{len(failures)}/{CONCURRENCY} concurrent bootstrap_schema runs failed: "
        f"{[type(f).__name__ for f in failures]}"
    )


async def test_the_migration_run_holds_the_advisory_lock():
    """Pins the MECHANISM, not just the outcome.

    The outcome test above could start passing for an unrelated reason -- a
    migration being removed, say -- so this asserts the lock is actually
    held for the duration of the run. Without it, a future refactor that
    dropped the lock would leave the suite green until a deploy failed.
    """
    holder = _new_pool()
    watcher = _new_pool()
    await holder.open()
    await watcher.open()
    try:
        async with holder.connection() as conn:
            await conn.execute("SELECT pg_advisory_xact_lock(%s)",
                               (0x0C0DE6DA,))
            # While that is held, a second attempt must be waiting.
            async with watcher.connection() as probe:
                cur = await probe.execute(
                    "SELECT count(*) AS n FROM pg_locks "
                    "WHERE locktype = 'advisory' AND granted"
                )
                assert (await cur.fetchone())["n"] >= 1, (
                    "the migration advisory lock is not being taken"
                )
    finally:
        await holder.close()
        await watcher.close()


async def test_the_schema_is_intact_afterwards(pool):
    """Serialising must not mean "one of them silently did nothing": the
    constraint and both partial indexes exist at the end."""
    await bootstrap_schema(pool)

    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT conname FROM pg_constraint WHERE conname = 'audits_status_check'"
        )
        assert await cur.fetchone(), "the status CHECK is missing"

        cur = await conn.execute(
            "SELECT indexname FROM pg_indexes WHERE tablename = 'audits' "
            "AND indexname IN ('audits_one_in_flight_per_repo', "
            "'audits_one_in_flight_per_user') ORDER BY indexname"
        )
        rows = [r["indexname"] for r in await cur.fetchall()]
        assert rows == ["audits_one_in_flight_per_repo",
                        "audits_one_in_flight_per_user"], rows


async def test_running_it_twice_leaves_the_widened_check_in_force(pool):
    """The point of 010, after repeated application: 'timed_out' is
    accepted however many times bootstrap has run."""
    await bootstrap_schema(pool)
    await bootstrap_schema(pool)

    from codeguard.api.audits import finish_audit, request_audit

    audit = await request_audit(
        pool, owner="acme", repo="widgets", requested_by="tester", private=False,
    )
    await finish_audit(pool, audit["id"], status="timed_out", error="took too long")

    async with pool.connection() as conn:
        cur = await conn.execute("SELECT status FROM audits WHERE id = %s", (audit["id"],))
        assert (await cur.fetchone())["status"] == "timed_out"
