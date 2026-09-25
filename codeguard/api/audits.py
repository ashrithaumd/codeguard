"""Reads and writes for the `audits` table.

Separate from dashboard_queries.py, which documents itself as read-only
and "the only place that SELECTs from `reviews`". Audits are read AND
written, and by two different processes: the api inserts the request,
the worker writes the result. Putting mutating queries into that module
would break the invariant its docstring is built on.

Ownership of each column is strict and worth stating once:

    api    inserts the row (queued), and never touches it again
    worker sets running, then exactly one of done / failed

Nothing else writes here. That split is what makes the partial unique
index a real lock rather than an optimistic hint -- see migration 009.
"""

from __future__ import annotations

import uuid
from typing import Any

from psycopg import errors
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

# Terminal states. A poll stops here, and the in-flight index does not
# cover them, so a repo in one of these can be audited again.
TERMINAL = ("done", "failed")

_COLUMNS = """
    id, owner, repo, requested_by, private, status, job_id,
    report_markdown, exit_code, error,
    tokens_in, tokens_out, estimated_cost_usd, duration_s,
    created_at, started_at, finished_at
"""


class AuditInFlight(Exception):
    """Raised instead of inserting a second audit for a repo that
    already has one queued or running.

    Carries the existing row so the caller can redirect to it rather
    than having to go and look it up again -- the user asked for an
    audit of this repo and there is one, which is a redirect, not an
    error page.
    """

    def __init__(self, existing: dict):
        self.existing = existing
        super().__init__(f"audit already in flight for {existing['owner']}/{existing['repo']}")


async def request_audit(
    pool: AsyncConnectionPool, *, owner: str, repo: str, requested_by: str, private: bool,
) -> dict:
    """Insert a queued audit, or raise AuditInFlight if one exists.

    The INSERT is the concurrency check. Nothing selects first: two tabs
    clicking at once both reach this, and the partial unique index from
    migration 009 decides which one wins. The loser catches
    UniqueViolation and reads the winner's row -- which by then is
    committed, because the constraint could not have fired otherwise.

    A SELECT-then-INSERT would let both see "nothing in flight" and both
    enqueue, which is the exact failure the index exists to prevent:
    two jobs, two clones, two lots of Anthropic spend, on one repo.
    """
    audit_id = uuid.uuid4()
    try:
        async with pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    f"""
                    INSERT INTO audits (id, owner, repo, requested_by, private, status)
                    VALUES (%s, %s, %s, %s, %s, 'queued')
                    RETURNING {_COLUMNS}
                    """,
                    (audit_id, owner, repo, requested_by, private),
                )
                return await cur.fetchone()
    except errors.UniqueViolation:
        pass

    # A SEPARATE connection, and the reason is not stylistic. psycopg
    # wraps `pool.connection()` in a transaction, and a constraint
    # violation aborts it: every further statement on that connection
    # fails with InFailedSqlTransaction until it unwinds. The recovery
    # read therefore cannot share the block that raised — it has to
    # happen after the rollback, on a connection that is not poisoned.
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT {_COLUMNS} FROM audits "
                "WHERE owner = %s AND repo = %s AND status IN ('queued', 'running') "
                "ORDER BY created_at DESC LIMIT 1",
                (owner, repo),
            )
            existing = await cur.fetchone()

    if existing is None:
        # The in-flight row finished between the violation and this read.
        # Genuinely rare, and retrying once is the honest response: the
        # constraint that blocked us no longer applies.
        return await request_audit(
            pool, owner=owner, repo=repo, requested_by=requested_by, private=private,
        )
    raise AuditInFlight(existing)


async def attach_job(pool: AsyncConnectionPool, audit_id, job_id) -> None:
    async with pool.connection() as conn:
        await conn.execute("UPDATE audits SET job_id = %s WHERE id = %s", (job_id, audit_id))


async def get_audit(pool: AsyncConnectionPool, audit_id) -> dict | None:
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(f"SELECT {_COLUMNS} FROM audits WHERE id = %s", (audit_id,))
            return await cur.fetchone()


async def mark_running(pool: AsyncConnectionPool, audit_id) -> None:
    """queued -> running, guarded on the current status.

    The WHERE clause matters on a redelivery: at-least-once means this
    job can arrive twice, and a second pass must not reset started_at on
    a row some other attempt already finished.
    """
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE audits SET status = 'running', started_at = now() "
            "WHERE id = %s AND status = 'queued'",
            (audit_id,),
        )


async def finish_audit(
    pool: AsyncConnectionPool, audit_id, *, status: str,
    report_markdown: str | None = None, exit_code: int | None = None,
    error: str | None = None, tokens_in: int = 0, tokens_out: int = 0,
    estimated_cost_usd: float = 0.0, duration_s: float = 0.0,
) -> None:
    """Write the terminal state. Releases the in-flight index entry, so
    this is also what makes the repo auditable again."""
    if status not in TERMINAL:
        raise ValueError(f"not a terminal status: {status!r}")
    async with pool.connection() as conn:
        await conn.execute(
            """
            UPDATE audits SET status = %s, report_markdown = %s, exit_code = %s,
                   error = %s, tokens_in = %s, tokens_out = %s,
                   estimated_cost_usd = %s, duration_s = %s, finished_at = now()
            WHERE id = %s
            """,
            (status, report_markdown, exit_code, error, tokens_in, tokens_out,
             estimated_cost_usd, duration_s, audit_id),
        )


async def latest_per_repo(pool: AsyncConnectionPool) -> dict[tuple[str, str], dict]:
    """The newest audit for every repo, keyed by (owner, repo).

    One query with DISTINCT ON rather than one per row on the
    repositories page -- the page already costs a GitHub call per repo
    for the visibility gate and does not need a database round trip per
    row on top.
    """
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT DISTINCT ON (owner, repo) {_COLUMNS} FROM audits "
                "ORDER BY owner, repo, created_at DESC"
            )
            return {(row["owner"], row["repo"]): row for row in await cur.fetchall()}


async def repo_stats(pool: AsyncConnectionPool) -> dict[tuple[str, str], dict[str, Any]]:
    """Review count, last review and total cost per repo.

    Deliberately UNFILTERED by visibility: the caller has the repo list
    it is allowed to render and looks rows up by key, so a repo the
    visitor cannot see is simply never asked for. Filtering here too
    would mean passing principal_repos through a third code path for no
    additional protection.
    """
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT owner, repo, count(*) AS review_count,
                       max(created_at) AS last_reviewed,
                       coalesce(sum(estimated_cost_usd), 0) AS total_cost
                FROM reviews GROUP BY owner, repo
                """
            )
            return {(row["owner"], row["repo"]): row for row in await cur.fetchall()}
