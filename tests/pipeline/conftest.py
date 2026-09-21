"""Shared Finding construction helper for pipeline tests — same pattern
as tests/tools/test_models.py and test_line_filter.py
(Finding.create with sensible defaults), centralized here so pipeline
tests don't each reinvent it.

`pool`: a real Postgres connection, for
tests/pipeline/test_hunk_cache.py only — mirrors tests/queue/conftest.py's
own fixture exactly (separate `codeguard_test` database, Windows event
loop policy fix), duplicated rather than imported across test packages
since the two are independent test suites that happen to need the same
setup, not a shared dependency between them.
"""

from __future__ import annotations

import asyncio
import os
import sys
from urllib.parse import urlsplit, urlunsplit

import pytest_asyncio
from psycopg_pool import AsyncConnectionPool

from codeguard.queue.db import MIGRATIONS_DIR, _configure_connection
from codeguard.severity import Severity
from codeguard.tools.models import Finding

# Derived from whatever DATABASE_URL is already set rather than
# os.environ.setdefault(): inside the containers compose has *already*
# set DATABASE_URL to the live `codeguard` database, so setdefault was a
# no-op there and the suite ran straight at the live queue -- producing
# exactly the DeadlockDetected on TRUNCATE described above. Swapping only
# the database name keeps the host default (localhost:5433) and the
# in-container one (db:5432) both pointed at codeguard_test.
# TEST_DATABASE_URL overrides outright, for a Postgres somewhere else.
_DEFAULT_DATABASE_URL = "postgresql://codeguard:codeguard_dev_only@localhost:5433/codeguard"


def _test_database_url() -> str:
    explicit = os.environ.get("TEST_DATABASE_URL")
    if explicit:
        return explicit
    parts = urlsplit(os.environ.get("DATABASE_URL") or _DEFAULT_DATABASE_URL)
    return urlunsplit(parts._replace(path="/codeguard_test"))


# Exported through the environment too, so anything under test that
# builds its own connection from Settings.database_url also lands on the
# test database rather than the live one.
os.environ["DATABASE_URL"] = _test_database_url()

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
        await conn.execute("TRUNCATE hunk_findings, posted_finding_comments, finding_feedback, suppressed_findings")
    yield p
    await p.close()


def make_finding(
    file: str = "a.py",
    line: int = 1,
    severity: Severity = Severity.MEDIUM,
    tool: str = "bandit",
    rule_id: str = "B000",
    message: str = "issue",
    confidence: float = 1.0,
) -> Finding:
    return Finding.create(
        file=file, start_line=line, end_line=line, severity=severity,
        source_tool=tool, rule_id=rule_id, message=message, confidence=confidence,
    )
