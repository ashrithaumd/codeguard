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
import contextlib
import os
import sys
from urllib.parse import urlsplit, urlunsplit

import pytest
import pytest_asyncio
from unittest import mock
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

# ONE statement, and the table list is alphabetical. Both parts matter.
#
# TRUNCATE takes ACCESS EXCLUSIVE and locks the tables in the order they
# are written, so N separate statements are N separate lock acquisitions
# that another backend can interleave with. This was three statements
# (reviews, then audits, then jobs) while tests/queue/conftest.py used a
# single `TRUNCATE jobs, dead_letters, audits` — opposite order on the
# two tables they share — and the result was an intermittent
# DeadlockDetected during fixture setup, surfacing as an ERROR on an
# unrelated test rather than as a failure anywhere near the cause.
#
# One statement makes the acquisition atomic; the shared alphabetical
# order means any future conftest that truncates an overlapping subset
# cannot invert it. tests/queue/conftest.py follows the same rule.
# tests/pipeline/conftest.py truncates a disjoint set, so it cannot
# participate in this deadlock and is left alone.
#
# This is the same failure mode the comment in tests/queue/conftest.py
# describes against the shared dev database — same lock, different
# reason for the contention.
_TRUNCATE = "TRUNCATE audits, jobs, reviews"

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
        await conn.execute(_TRUNCATE)
    yield p
    await p.close()


TEST_PRINCIPAL = "test-user"


@contextlib.contextmanager
def _identity(principal: str | None, *, collaborator: bool):
    """Patch who the visitor is, and what GitHub says about them.

    Both together, always. The pair is what stops a test from passing
    vacuously: a principal with no collaborator answer sends the access
    path to the live GitHub API, and a collaborator answer with no
    principal is never consulted.

    Goes through the dev-principal settings rather than injecting the
    header, so it exercises the same path a local dev run does and
    inherits client_principal's two-key requirement.
    """
    from codeguard.api import access
    from codeguard.config import Settings, get_settings

    base = get_settings().model_dump()
    base.update({
        "dashboard_dev_principal": principal or "",
        "dashboard_trust_dev_principal": bool(principal),
    })
    patched = Settings(**base)
    with mock.patch("codeguard.api.auth.get_settings", lambda: patched), \
         mock.patch.object(access, "_is_collaborator", return_value=collaborator):
        yield


@contextlib.asynccontextmanager
async def _client(pool, principal: str | None, collaborator: bool):
    from fastapi.testclient import TestClient

    from codeguard.api import access
    from codeguard.api.main import app

    access.reset_caches()
    app.state.pool = pool
    async with pool.connection() as conn:
        await conn.execute(_TRUNCATE)
    with _identity(principal, collaborator=collaborator):
        with TestClient(app) as c:
            app.state.pool = pool
            yield c
    access.reset_caches()


@pytest.fixture
async def client(pool):
    """A TestClient wired to the test-database pool, SIGNED IN with access.

    Authenticated by default, deliberately. The dashboard requires an
    access decision on every row now — public repositories included,
    since the page aggregates what a single public review does not
    disclose — so "signed in and allowed" is the state in which almost
    every page has any content to assert about.

    The alternative, an anonymous default, was actively dangerous here: a
    test asserting some element is ABSENT would pass because the whole
    page was empty, which is exactly the failure that let
    test_the_button_is_absent_for_a_user_who_may_not_audit pass while
    observing nothing. Anonymity is now opt-in via `anon_client`, so a
    test that means to check it has to say so.

    TestClient's own lifespan would rebuild app.state.pool against the
    live database, so the fixture's pool is reinstated after startup.
    """
    async with _client(pool, TEST_PRINCIPAL, collaborator=True) as c:
        yield c


@pytest.fixture
async def anon_client(pool):
    """A TestClient with no identity, for the tests that are about that.

    _is_collaborator returns False as well as there being no principal —
    belt and braces, so a test cannot accidentally depend on the access
    path being reached at all.
    """
    async with _client(pool, None, collaborator=False) as c:
        yield c


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
        estimated_cost_usd=0.0,
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
                budget_exceeded, findings_json, fix_suggestions_json, pr_title,
                estimated_cost_usd
            ) VALUES (%s,%s,%s,%s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s, %s,%s,%s,%s,
                      %s,%s,%s, %s,%s,%s,%s,%s)
            """,
            (row["job_id"], row["owner"], row["repo"], row["pr_number"], row["head_sha"],
             row["action"], row["private"], row["summary_body"], row["check_conclusion"],
             row["gate_threshold"], row["fix_threshold"], row["files_seen"],
             row["files_reviewed"], row["findings_total"], row["vc"], row["gen"],
             row["det"], row["unv"], row["dismissed_count"], row["inline_count"],
             row["fix_suggestion_count"], row["budget_exceeded"],
             Jsonb(row["findings"]), Jsonb(row["fixes"]), row["pr_title"],
             row["estimated_cost_usd"]),
        )
    return row["job_id"]
