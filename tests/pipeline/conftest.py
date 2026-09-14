"""Shared Finding construction helper for pipeline tests — same pattern
as Phase 4's tests/tools/test_models.py and test_line_filter.py
(Finding.create with sensible defaults), centralized here so pipeline
tests don't each reinvent it.

`pool` (Phase 7): a real Postgres connection, for
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

import pytest_asyncio
from psycopg_pool import AsyncConnectionPool

from codeguard.queue.db import MIGRATIONS_DIR, _configure_connection
from codeguard.severity import Severity
from codeguard.tools.models import Finding

os.environ.setdefault("DATABASE_URL", "postgresql://codeguard:codeguard_dev_only@localhost:5433/codeguard_test")

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
        await conn.execute("TRUNCATE hunk_findings")
    yield p
    await p.close()


def make_finding(
    file: str = "a.py",
    line: int = 1,
    severity: Severity = Severity.MEDIUM,
    tool: str = "bandit",
    rule_id: str = "B000",
    message: str = "issue",
) -> Finding:
    return Finding.create(
        file=file, start_line=line, end_line=line, severity=severity,
        source_tool=tool, rule_id=rule_id, message=message,
    )
