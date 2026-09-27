"""Connection pool + schema bootstrap, shared by the API and worker.

Ported from Reliqueue's core/db.py, translated from asyncpg to psycopg3 +
psycopg_pool: this project already uses psycopg3 for its own /ready
check, and running two different Postgres drivers in one small codebase
for no functional benefit isn't worth the maintenance cost.

Two translation details worth being explicit about, since they're the
easiest place to introduce a silent bug while porting:
  - psycopg3 uses %s positional placeholders, not asyncpg's $1/$2.
  - Row shape: psycopg3's default cursor returns plain tuples, not
    dict-like rows. `_configure_connection` sets `row_factory = dict_row`
    on every new connection so the rest of this package can treat rows
    as dicts, matching Job.from_record()'s expectations.
"""

from __future__ import annotations

from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from codeguard.config import Settings, get_settings

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "migrations"


async def _configure_connection(conn: psycopg.AsyncConnection) -> None:
    conn.row_factory = dict_row


async def create_pool(settings: Settings | None = None) -> AsyncConnectionPool:
    """Small, configurable-per-process pool — see Settings.queue_pool_max_size
    for why this must stay small rather than copying Reliqueue's local-dev
    default of 10: this size is paid N times over at `--scale worker=N`
    against a managed Postgres tier with a hard total connection cap.
    """
    settings = settings or get_settings()
    pool = AsyncConnectionPool(
        settings.database_url,
        min_size=settings.queue_pool_min_size,
        max_size=settings.queue_pool_max_size,
        kwargs={"sslmode": settings.db_sslmode},
        configure=_configure_connection,
        open=False,
    )
    await pool.open()
    return pool


# Arbitrary but fixed: any two processes running migrations must pick the
# same number for the lock to mean anything. Advisory locks live in their
# own namespace, so this cannot collide with a table lock.
_MIGRATION_LOCK_KEY = 0x0C0DE6DA


async def bootstrap_schema(pool: AsyncConnectionPool) -> None:
    """Apply every migrations/*.sql file in order, one process at a time.

    Called at startup by BOTH the api (lifespan) and the worker (main), and
    a deploy starts them simultaneously. Without serialisation that fails:
    measured against this schema, SIX concurrent runs produced FOUR
    DeadlockDetected failures. The whole run is one transaction touching
    seven tables, so two runs acquire overlapping locks and Postgres breaks
    the cycle by killing a victim -- whose migration rolls back and whose
    container then fails to start. An intermittently failing deploy, which
    is the worst kind to diagnose.

    This docstring used to claim safety because "migrations use
    CREATE ... IF NOT EXISTS". That was true of 001-009 and MIGRATION 010
    BROKE IT: a CHECK constraint cannot be widened in place, so it drops and
    re-adds. The deadlock is the more general problem though -- it does not
    need 010 at all, only two runs and enough tables.

    pg_advisory_xact_lock rather than per-statement idempotence:
      * it protects EVERY migration, including ones not yet written, rather
        than the one that happened to expose the gap
      * it is released automatically at transaction end, so a crashed
        process cannot leave the lock held
      * the second process waits and then does a no-op run, which is the
        behaviour we want anyway

    The lock is taken INSIDE the same transaction as the migrations, so it
    is held for the whole run and released by the commit.
    """
    sql_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    async with pool.connection() as conn:
        # First, before any DDL: the point is to hold it for everything
        # below, and an advisory lock in the same transaction does that.
        await conn.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_LOCK_KEY,))
        for path in sql_files:
            await conn.execute(path.read_text())
