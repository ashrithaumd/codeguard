"""Fixtures for codeguard/queue tests. Runs against a real Postgres — no
mocking of SKIP LOCKED / row-level locking semantics; that's the entire
point of these tests. Defaults to docker-compose's Postgres on its
host-published port.

`pool` is function-scoped (a fresh pool per test, truncated up front)
rather than session-scoped: pytest-asyncio gives each test its own event
loop by default, and a pool created on one loop can't be used from
another — function scope keeps the pool and the test on the same loop
with zero extra fixture machinery.
"""

from __future__ import annotations

import asyncio
import os
import sys

import pytest_asyncio
from psycopg_pool import AsyncConnectionPool

from codeguard.queue.db import MIGRATIONS_DIR, _configure_connection

# A separate database from the one docker-compose's live api/worker
# containers use, on the same Postgres server — not just for hygiene.
# Running tests against the shared dev database caused a real, observed
# DeadlockDetected on TRUNCATE (a test's exclusive lock racing the live
# reaper/workers' ongoing queries against the same jobs table) — this
# isn't a hypothetical isolation concern, it actually happened.
os.environ.setdefault("DATABASE_URL", "postgresql://codeguard:codeguard_dev_only@localhost:5433/codeguard_test")

# Windows-only: asyncio's default loop there is ProactorEventLoop, which
# psycopg3's async mode cannot use at all ("Psycopg cannot use the
# 'ProactorEventLoop' to run in async mode"). This is purely a local-dev
# test-runner concern on this platform — the actual containers run Linux,
# where this doesn't exist. Must be set before pytest-asyncio creates its
# first event loop, hence at conftest module-import time.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


@pytest_asyncio.fixture
async def pool():
    p = AsyncConnectionPool(
        os.environ["DATABASE_URL"], min_size=2, max_size=10,
        configure=_configure_connection, open=False,
    )
    await p.open()
    async with p.connection() as conn:
        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            await conn.execute(path.read_text())
        await conn.execute("TRUNCATE jobs, dead_letters")
    yield p
    await p.close()
