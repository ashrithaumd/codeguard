"""Read queries behind the dashboard. Read-only, and the only place
that SELECTs from `reviews`.

Separate from queue/db.py because that module owns the queue's
read-WRITE path and its transactional semantics; nothing here writes,
and nothing here should ever start.

Two access-control rules are enforced in SQL rather than in Python:

  - the index and repo listings take `principal_repos`, the set of
    private repos this visitor may see, and filter to `NOT private OR
    (owner, repo) IN (...)`. Filtering after the fetch would mean a
    LIMIT 50 could return 3 visible rows, and paging would be wrong in
    a way that leaks the shape of what is hidden.
  - the single-review fetch does NOT filter. It returns the row with
    its `private` flag and the route decides, because the route needs
    to tell "no such review" from "not yours" — and then deliberately
    answer 404 for both.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

# Columns the listings need. summary_body and the JSONB detail columns
# are deliberately absent: a 50-row index page has no use for 50 review
# bodies, and fetching them would make the list query's cost scale with
# the size of the reviews rather than their number.
_LIST_COLUMNS = """
    job_id, owner, repo, pr_number, head_sha, action, private,
    check_conclusion, gate_threshold, fix_threshold,
    files_seen, files_reviewed, findings_total,
    findings_verdict_confirmed, findings_generative,
    findings_deterministic, findings_unverified,
    dismissed_count, inline_count, fix_suggestion_count,
    budget_exceeded, tokens_in, tokens_out, estimated_cost_usd,
    duration_s, created_at
"""


def _visibility_clause(principal_repos: list[tuple[str, str]], params: list[Any]) -> str:
    """`NOT private` for anonymous visitors, widened by an explicit list
    of (owner, repo) pairs the visitor has been cleared for.

    The pairs are passed as parameters, never interpolated — they
    originate in review rows, which carry repo names a PR author can
    influence.
    """
    if not principal_repos:
        return "NOT private"
    placeholders = ", ".join(["(%s, %s)"] * len(principal_repos))
    for owner, repo in principal_repos:
        params.extend([owner, repo])
    return f"(NOT private OR (owner, repo) IN ({placeholders}))"


async def list_reviews(
    pool: AsyncConnectionPool, *, principal_repos: list[tuple[str, str]],
    limit: int = 50, offset: int = 0,
) -> list[dict]:
    params: list[Any] = []
    where = _visibility_clause(principal_repos, params)
    params.extend([limit, offset])
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT {_LIST_COLUMNS} FROM reviews WHERE {where} "
                f"ORDER BY created_at DESC LIMIT %s OFFSET %s",
                params,
            )
            return await cur.fetchall()


async def count_reviews(pool: AsyncConnectionPool, *, principal_repos: list[tuple[str, str]]) -> int:
    params: list[Any] = []
    where = _visibility_clause(principal_repos, params)
    # Named, not positional: queue/db.py's _configure_connection sets
    # row_factory = dict_row on every pooled connection, so row[0] is a
    # KeyError rather than the first column.
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(f"SELECT count(*) AS n FROM reviews WHERE {where}", params)
            row = await cur.fetchone()
            return row["n"] if row else 0


async def list_repos(pool: AsyncConnectionPool, *, principal_repos: list[tuple[str, str]]) -> list[dict]:
    """One row per repo for the index's filter, with enough to be worth
    showing on its own: how many reviews, what they cost, when last seen.
    """
    params: list[Any] = []
    where = _visibility_clause(principal_repos, params)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"""
                SELECT owner, repo,
                       count(*)                        AS review_count,
                       sum(estimated_cost_usd)         AS total_cost,
                       sum(findings_total)             AS total_findings,
                       max(created_at)                 AS last_reviewed,
                       bool_or(private)                AS private
                FROM reviews WHERE {where}
                GROUP BY owner, repo
                ORDER BY max(created_at) DESC
                """,
                params,
            )
            return await cur.fetchall()


async def get_review(pool: AsyncConnectionPool, job_id: UUID) -> dict | None:
    """Every column, including the JSONB detail. No visibility filter —
    see this module's docstring.
    """
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("SELECT * FROM reviews WHERE job_id = %s", (job_id,))
            return await cur.fetchone()


async def repo_history(
    pool: AsyncConnectionPool, *, owner: str, repo: str, limit: int = 100,
) -> list[dict]:
    """One repo's reviews, newest-first to match the table that renders
    them; the template reverses for the chart, which reads left to right.

    tokens_in is what makes the hunk cache visible: a re-review of an
    unchanged file reuses cached agent results, so the second review of
    a PR costs a fraction of the first. 006's own docstring calls that
    out as the thing nothing could currently show.
    """
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT {_LIST_COLUMNS} FROM reviews WHERE owner = %s AND repo = %s "
                f"ORDER BY created_at DESC LIMIT %s",
                (owner, repo, limit),
            )
            return await cur.fetchall()


async def distinct_private_repos(pool: AsyncConnectionPool) -> list[tuple[str, str]]:
    """Every private (owner, repo) that has a review row.

    The set a visitor must be checked against. Deliberately the DISTINCT
    repos rather than the rows: a repo with 200 reviews is one GitHub
    question, not 200. Typically a handful of entries, and
    access.can_view caches each answer, so a page view costs at most one
    call per private repo the first time and none thereafter.
    """
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute("SELECT DISTINCT owner, repo FROM reviews WHERE private")
            return [(row["owner"], row["repo"]) for row in await cur.fetchall()]
