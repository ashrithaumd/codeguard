""""New repository" notices (migrations/015).

Written by the webhook from installation / installation_repositories
events; read and dismissed on the Repositories page, by operators only.
A plain `git clone` creates nothing on GitHub and sends no event, so it can
never produce one.
"""

from __future__ import annotations

from psycopg_pool import AsyncConnectionPool


async def announce(pool: AsyncConnectionPool, repos: list[tuple[str, str, bool]]) -> None:
    """One notice per (owner, repo, private). Existing rows are left alone,
    so a redelivery neither duplicates a notice nor revives a dismissed one."""
    if not repos:
        return
    async with pool.connection() as conn:
        for owner, repo, private in repos:
            await conn.execute(
                "INSERT INTO repo_notices (owner, repo, private) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING",
                (owner, repo, private),
            )


async def forget(pool: AsyncConnectionPool, repos: list[tuple[str, str]]) -> None:
    """The repository left the installation: drop its notice entirely, so
    adding it back later announces it again."""
    if not repos:
        return
    async with pool.connection() as conn:
        for owner, repo in repos:
            await conn.execute(
                "DELETE FROM repo_notices WHERE lower(owner) = lower(%s) AND lower(repo) = lower(%s)",
                (owner, repo),
            )


async def pending(pool: AsyncConnectionPool) -> list[dict]:
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT owner, repo, private, added_at FROM repo_notices "
            "WHERE dismissed_at IS NULL ORDER BY added_at DESC, owner, repo"
        )
        return [dict(r) for r in await cur.fetchall()]


async def dismiss(pool: AsyncConnectionPool, owner: str, repo: str, *, dismissed_by: str) -> None:
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE repo_notices SET dismissed_at = now(), dismissed_by = %s "
            "WHERE lower(owner) = lower(%s) AND lower(repo) = lower(%s) AND dismissed_at IS NULL",
            (dismissed_by, owner, repo),
        )


async def dismiss_all(pool: AsyncConnectionPool, *, dismissed_by: str) -> None:
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE repo_notices SET dismissed_at = now(), dismissed_by = %s WHERE dismissed_at IS NULL",
            (dismissed_by,),
        )
