"""Feedback loop — see migrations/005_finding_feedback.sql for
the table shapes and why fingerprint (not comment_id) is the identity
a suppression is keyed on.

Signal parsing (parse_feedback_signal) is a pure function, directly
unit-testable; everything else here is DB access, called only from
codeguard/api/routes/webhooks.py (recording feedback, on every
recognized reply — no installation token needed, everything comes
straight off the webhook payload) and codeguard/worker/main.py
(persisting the comment_id -> fingerprint mapping right after posting,
and fetching suppressed fingerprints before running the review graph).
"""

from __future__ import annotations

import re

from psycopg_pool import AsyncConnectionPool

# Embedded in every inline finding comment's body (see worker/main.py's
# _findings_to_review_comments) — invisible in GitHub's rendered
# markdown, but round-trips through the API's plain-text `body` field,
# so a later fetch of that same comment can recover exactly which
# finding it was about without a second lookup table keyed by
# path+line+message (which drifts if two findings ever collide on
# those — fingerprint already can't, by construction).
FINGERPRINT_MARKER_RE = re.compile(r"<!-- codeguard-fingerprint:([0-9a-f]{16}) -->")


def fingerprint_marker(fingerprint: str) -> str:
    return f"<!-- codeguard-fingerprint:{fingerprint} -->"


def parse_feedback_signal(body: str) -> str | None:
    """None when the comment isn't recognized feedback at all — the
    overwhelming majority of replies, which are just conversation and
    should never be recorded as a signal. Checked in this order because
    a reply reasonably could say "false positive :+1: agreed" — the
    stronger, more specific "false_positive" signal should win over a
    plain thumbs-up in that case, not the other way around.

    No @mention of the bot's own handle is required — a reply already
    has to land in a thread on one of our own comments (or, for a
    fingerprint-less issue_comment, be treated as general conversation
    otherwise) to be considered at all, so the mention would be
    redundant context, not a disambiguator. See this module's own
    docstring and the webhook handlers for the reply-vs-reaction
    distinction this is built around.
    """
    lower = body.lower()
    if "false positive" in lower or "false-positive" in lower:
        return "false_positive"
    if "\U0001F44E" in body:  # 👎
        return "negative"
    if "\U0001F44D" in body:  # 👍
        return "positive"
    return None


async def record_posted_finding_comments(
    pool: AsyncConnectionPool, owner: str, repo: str, pr_number: int, comment_id_by_fingerprint: dict[int, str],
) -> None:
    if not comment_id_by_fingerprint:
        return
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            for comment_id, fingerprint in comment_id_by_fingerprint.items():
                await cur.execute(
                    """
                    INSERT INTO posted_finding_comments (owner, repo, comment_id, pr_number, fingerprint)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (owner, repo, comment_id) DO NOTHING
                    """,
                    (owner, repo, comment_id, pr_number, fingerprint),
                )


async def fetch_fingerprint_for_comment(pool: AsyncConnectionPool, owner: str, repo: str, comment_id: int) -> str | None:
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT fingerprint FROM posted_finding_comments WHERE owner = %s AND repo = %s AND comment_id = %s",
                (owner, repo, comment_id),
            )
            row = await cur.fetchone()
    return row["fingerprint"] if row else None


async def record_feedback(
    pool: AsyncConnectionPool, *, owner: str, repo: str, fingerprint: str | None, pr_number: int,
    comment_id: int, commenter: str, signal: str, body: str, source_event: str,
) -> None:
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO finding_feedback
                    (owner, repo, fingerprint, pr_number, comment_id, commenter, signal, body, source_event)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (owner, repo, fingerprint, pr_number, comment_id, commenter, signal, body, source_event),
            )


async def suppress_fingerprint(
    pool: AsyncConnectionPool, *, owner: str, repo: str, fingerprint: str, reason: str, suppressed_by: str,
) -> None:
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO suppressed_findings (owner, repo, fingerprint, reason, suppressed_by)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (owner, repo, fingerprint) DO NOTHING
                """,
                (owner, repo, fingerprint, reason, suppressed_by),
            )


async def fetch_suppressed_fingerprints(pool: AsyncConnectionPool, owner: str, repo: str) -> set[str]:
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT fingerprint FROM suppressed_findings WHERE owner = %s AND repo = %s",
                (owner, repo),
            )
            rows = await cur.fetchall()
    return {row["fingerprint"] for row in rows}
