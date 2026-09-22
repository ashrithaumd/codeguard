"""Fixtures for the API tests.

`pool` mirrors tests/queue/conftest.py and tests/pipeline/conftest.py
exactly — a real Postgres on the separate `codeguard_test` database,
function-scoped so the pool and the test share an event loop. Duplicated
rather than imported across test packages for the same reason those two
duplicate it: they are independent suites that happen to need the same
setup, not a shared dependency.

Truncates `reviews` rather than the queue tables, since that is the only
table these tests touch.
"""

from __future__ import annotations

import asyncio
import os
import sys
from urllib.parse import urlsplit, urlunsplit

import pytest_asyncio
from psycopg_pool import AsyncConnectionPool

from codeguard.queue.db import MIGRATIONS_DIR, _configure_connection

_DEFAULT_DATABASE_URL = "postgresql://codeguard:codeguard_dev_only@localhost:5433/codeguard"


def _test_database_url() -> str:
    explicit = os.environ.get("TEST_DATABASE_URL")
    if explicit:
        return explicit
    parts = urlsplit(os.environ.get("DATABASE_URL") or _DEFAULT_DATABASE_URL)
    return urlunsplit(parts._replace(path="/codeguard_test"))


os.environ["DATABASE_URL"] = _test_database_url()

# Windows-only: psycopg3's async mode cannot use ProactorEventLoop, and
# it is the default there. Must run before pytest-asyncio builds its
# first loop, hence at conftest import time.
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
        await conn.execute("TRUNCATE reviews")
    yield p
    await p.close()
