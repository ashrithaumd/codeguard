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

import pytest
import pytest_asyncio
import uuid
from psycopg.types.json import Jsonb
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


@pytest.fixture
async def client(pool):
    """A TestClient wired to the test-database pool.

    TestClient's own lifespan would rebuild app.state.pool against the
    live database, so the fixture's pool is reinstated after startup.
    """
    from fastapi.testclient import TestClient

    from codeguard.api import access
    from codeguard.api.main import app

    access.reset_caches()
    app.state.pool = pool
    async with pool.connection() as conn:
        await conn.execute("TRUNCATE reviews")
    with TestClient(app) as c:
        app.state.pool = pool
        yield c
    access.reset_caches()


async def insert_review(pool, **over):
    """One review row, with everything defaulted except what a test
    actually cares about.
    """
    row = dict(
        job_id=uuid.uuid4(), owner="acme", repo="widgets", pr_number=7,
        head_sha="a" * 40, action="opened", private=False,
        summary_body="all good", check_conclusion="success",
        gate_threshold="CRITICAL", fix_threshold="HIGH",
        files_seen=1, files_reviewed=1, findings_total=0,
        vc=0, gen=0, det=0, unv=0,
        dismissed_count=0, inline_count=0, fix_suggestion_count=0,
        budget_exceeded=False, findings=[], fixes=[], pr_title="",
    )
    row.update(over)
    async with pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO reviews (
                job_id, owner, repo, pr_number, head_sha, action, private,
                summary_body, check_conclusion, gate_threshold, fix_threshold,
                files_seen, files_reviewed, findings_total,
                findings_verdict_confirmed, findings_generative,
                findings_deterministic, findings_unverified,
                dismissed_count, inline_count, fix_suggestion_count,
                budget_exceeded, findings_json, fix_suggestions_json, pr_title
            ) VALUES (%s,%s,%s,%s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s, %s,%s,%s,%s,
                      %s,%s,%s, %s,%s,%s,%s)
            """,
            (row["job_id"], row["owner"], row["repo"], row["pr_number"], row["head_sha"],
             row["action"], row["private"], row["summary_body"], row["check_conclusion"],
             row["gate_threshold"], row["fix_threshold"], row["files_seen"],
             row["files_reviewed"], row["findings_total"], row["vc"], row["gen"],
             row["det"], row["unv"], row["dismissed_count"], row["inline_count"],
             row["fix_suggestion_count"], row["budget_exceeded"],
             Jsonb(row["findings"]), Jsonb(row["fixes"]), row["pr_title"]),
        )
    return row["job_id"]
