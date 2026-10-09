"""Per-repository settings (migrations/014): the "PR reviews" switch.

Read in two places, deliberately:

  routes/webhooks.py   the gate: a delivery for a repository that is OFF is
                       acknowledged and never queued
  worker/main.py       the re-check: a job queued while the switch was ON
                       and claimed after it was turned OFF is acked without
                       minting a token or calling a model

Written in one: the dashboard's operator-only POST.

No row means OFF. Names match case-insensitively, like GitHub's.
"""

from __future__ import annotations

from psycopg_pool import AsyncConnectionPool


async def pr_reviews_enabled(pool: AsyncConnectionPool, owner: str, repo: str) -> bool:
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT pr_reviews_enabled FROM repo_settings "
            "WHERE lower(owner) = lower(%s) AND lower(repo) = lower(%s)",
            (owner, repo),
        )
        row = await cur.fetchone()
    return bool(row and row["pr_reviews_enabled"])


async def pr_reviews_map(pool: AsyncConnectionPool) -> dict[tuple[str, str], bool]:
    """Every stored switch, keyed by lowercased (owner, repo), for the
    repositories page: one query for the whole table, not one per row."""
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT owner, repo, pr_reviews_enabled FROM repo_settings")
        rows = await cur.fetchall()
    return {(r["owner"].lower(), r["repo"].lower()): r["pr_reviews_enabled"] for r in rows}


async def set_pr_reviews(
    pool: AsyncConnectionPool, owner: str, repo: str, *, enabled: bool, updated_by: str,
) -> None:
    async with pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO repo_settings (owner, repo, pr_reviews_enabled, updated_by)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (lower(owner), lower(repo)) DO UPDATE
               SET pr_reviews_enabled = EXCLUDED.pr_reviews_enabled,
                   updated_by = EXCLUDED.updated_by,
                   updated_at = now()
            """,
            (owner, repo, enabled, updated_by),
        )
