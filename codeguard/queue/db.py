"""Connection pool + schema bootstrap, shared by the API and worker.

Ported from Reliqueue's core/db.py, translated from asyncpg to psycopg3 +
psycopg_pool — see the Phase 2 audit for why: this project already uses
psycopg3 for its own /ready check, and running two different Postgres
drivers in one small codebase for no functional benefit isn't worth the
maintenance cost.

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


async def bootstrap_schema(pool: AsyncConnectionPool) -> None:
    """Apply every migrations/*.sql file in order. Migrations use
    CREATE ... IF NOT EXISTS, so this is safe to run on every process
    startup (api, worker) with no external migration runner needed.
    """
    sql_files = sorted(MIGRATIONS_DIR.glob("*.sql"))
    async with pool.connection() as conn:
        for path in sql_files:
            await conn.execute(path.read_text())
