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
import hashlib
import os
import sys
from urllib.parse import urlsplit, urlunsplit

import pytest
import pytest_asyncio
from unittest import mock
import uuid
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from codeguard.config import Settings, get_settings
from codeguard.queue.db import _configure_connection, bootstrap_schema

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
# Alphabetical, one statement — see the comment above.
_TRUNCATE = "TRUNCATE audits, github_user_tokens, jobs, reviews"

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
    # bootstrap_schema, NOT a hand-rolled copy of its loop.
    #
    # This WAS the loop, inlined, and that made it the one migration
    # runner in the codebase that does not take
    # pg_advisory_xact_lock(_MIGRATION_LOCK_KEY). The api's TestClient
    # lifespan calls the real bootstrap_schema against this same test
    # database, so an unlocked copy here raced a locked one there and
    # produced DeadlockDetected in fixture setup -- reported against
    # whichever unrelated test happened to be next.
    #
    # Exactly the failure the advisory lock was added to prevent, reached
    # by writing a second implementation that opted out of it. The lesson
    # is the general one: a lock is only a lock if every path takes it.
    await bootstrap_schema(p)
    async with p.connection() as conn:
        await conn.execute(_TRUNCATE)
    yield p
    await p.close()


TEST_PRINCIPAL = "test-user"


# Real ids for the accounts these tests name. Real rather than invented
# because the defect that moved the allow-list to ids was found in exactly
# this pair -- both carry the display name "Ashritha Pola", so before the fix
# they were one indistinguishable principal.
REAL_IDS = {
    "ashrithaumd": "183667058",
    "ashrithapola": "60956648",
}


def principal_id(login: str) -> str:
    """The numeric id for a test login: the real one where it exists, and a
    stable synthetic otherwise.

    Deterministic, so the same login always yields the same id across files
    and runs, and distinct, so two different logins can never collide into
    one operator.

    sha256, NOT the builtin hash(): str.__hash__ is salted per process
    unless PYTHONHASHSEED is fixed, so ids would have differed run to run —
    which for a value that decides operator rights in a test is the kind of
    flakiness that gets diagnosed twice and understood neither time.
    """
    known = REAL_IDS.get(login.lower())
    if known:
        return known
    digest = hashlib.sha256(login.lower().encode()).hexdigest()
    # Offset well clear of the real ids above so a synthetic can never
    # accidentally equal one.
    return str(900_000_000 + int(digest[:8], 16) % 10_000_000)


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
        # The same login -> id mapping as_principal uses, so the default
        # signed-in client and an as_principal one describe the same person.
        # Note it grants nothing on its own: operator rights come from the
        # allow-list, which this leaves alone.
        "dashboard_dev_principal_id": principal_id(principal) if principal else "",
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


# ---------------------------------------------------------------------------
# Signing a visitor in, and the login -> numeric id mapping that needs.
#
# ONE fixture, in conftest, replacing three identical copies that lived in
# test_repositories.py, test_csrf.py and test_audit_ownership.py. They had to
# be consolidated rather than each given the same new field: the operator
# allow-list now matches GitHub's immutable numeric id rather than the login
# (Settings.dashboard_audit_principals), so every one of them needs a
# login -> id mapping, and three copies of a mapping is three chances for a
# test to mean "the operator" while another means someone else.
# ---------------------------------------------------------------------------



@pytest.fixture
def as_principal(monkeypatch):
    """Sign a visitor in without EasyAuth, via the existing dev override.

    Uses the two-key form the setting requires -- a username AND an explicit
    trust flag -- rather than injecting headers, so the test exercises the
    same path a local dev run does.

    `audit_principals` is given here as LOGINS and translated to ids, purely
    so these tests stay readable. THAT TRANSLATION IS A TEST CONVENIENCE AND
    NOT THE PRODUCTION RULE: a login in DASHBOARD_AUDIT_PRINCIPALS is inert,
    which tests/api/test_identity.py pins directly against Settings
    (test_the_allow_list_refuses_a_login_entirely).
    """
    def _sign_in(login: str | None, *, audit_principals: str = ""):
        allowed_ids = ",".join(
            principal_id(entry.strip())
            for entry in audit_principals.split(",")
            if entry.strip()
        )
        base = get_settings().model_dump()
        base.update({
            "dashboard_dev_principal": login or "",
            "dashboard_dev_principal_id": principal_id(login) if login else "",
            "dashboard_trust_dev_principal": bool(login),
            "dashboard_audit_principals": allowed_ids,
        })
        patched = Settings(**base)
        monkeypatch.setattr("codeguard.api.auth.get_settings", lambda: patched)
        monkeypatch.setattr("codeguard.api.routes.dashboard.get_settings", lambda: patched)
        return patched
    return _sign_in
