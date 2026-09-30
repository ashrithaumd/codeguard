"""Storage for GitHub user-to-server tokens.

Phase 2 needs one to list a visitor's OWN repositories: an installation token
is scoped to the installation, not to the person looking at the page, so it
cannot answer "which repos are yours".

This is the first credential this application stores, and the rules that
follow from that are in migrations/011_github_user_tokens.sql. The one worth
repeating here: the token reaches no cookie, no response body, no header and
no log line. Nothing in this module returns it to anything but a caller that
is about to use it against GitHub, and no route does that yet.

Keyed on the numeric user id, never the login — a login can be renamed and
re-registered by somebody else, and a row keyed on one would then belong to
the wrong person.
"""

from __future__ import annotations

import logging
from datetime import datetime

from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)


async def store(
    pool: AsyncConnectionPool, *, user_id: str, login: str, access_token: str,
    expires_at: datetime | None = None, refresh_token: str | None = None,
) -> None:
    """Record this person's token, replacing any previous one.

    An upsert rather than an insert: one live credential per person means no
    history of superseded tokens sitting in the table to be leaked.

    Refuses an empty id or token rather than writing a row. A row keyed on an
    empty id would be a single shared credential for everybody whose id we
    failed to read, which is the kind of bug that works fine until it does
    not.
    """
    if not user_id:
        raise ValueError("refusing to store a token with no user id")
    if not access_token:
        raise ValueError("refusing to store an empty token")

    async with pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO github_user_tokens
                (user_id, login, access_token, expires_at, refresh_token, updated_at)
            VALUES (%s, %s, %s, %s, %s, now())
            ON CONFLICT (user_id) DO UPDATE SET
                login = EXCLUDED.login,
                access_token = EXCLUDED.access_token,
                expires_at = EXCLUDED.expires_at,
                refresh_token = EXCLUDED.refresh_token,
                updated_at = now()
            """,
            (user_id, login, access_token, expires_at, refresh_token),
        )
    # The id and login, never the token. Both are public facts about the
    # account; the token is the credential.
    logger.info("stored a GitHub user token for %s (id=%s)", login, user_id)


async def get(pool: AsyncConnectionPool, user_id: str | None) -> str | None:
    """This person's token, or None.

    No expiry filtering here: nothing consumes these yet, and a caller that
    does will need to decide between refreshing and re-prompting, which is a
    decision that belongs with the caller rather than hidden in a getter.
    """
    if not user_id:
        return None
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT access_token FROM github_user_tokens WHERE user_id = %s", (user_id,),
        )
        row = await cur.fetchone()
    return row["access_token"] if row else None
