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

import logging
import uuid
from typing import Any

from psycopg import errors
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger(__name__)

# Terminal states. A poll stops here, and neither partial unique index
# covers them, so a repo (and a requester) in one of these is free again.
#
# 'rejected' is refused-before-the-work: too large, not public, no Python,
# demo budget exhausted. 'failed' is tried-and-broke. Both are terminal --
# the distinction is what the page tells the user to do next, not whether
# the audit is over. See migration 010.
TERMINAL = ("done", "failed", "rejected", "timed_out")

# cli.AuditOutcome -> audits.status. The worker maps through this table and
# NEVER by reading a message, so rewording user-facing copy cannot change
# how an audit is stored. See migration 011 for why timed_out is its own
# status rather than a flavour of 'failed'.
OUTCOME_TO_STATUS = {
    "completed": "done",
    "rejected": "rejected",
    "timed_out": "timed_out",
    "failed": "failed",
}

_COLUMNS = """
    id, owner, repo, requested_by, private, status, job_id,
    report_markdown, report_json, exit_code, error,
    tokens_in, tokens_out, estimated_cost_usd, duration_s,
    created_at, started_at, finished_at
"""


class AuditInFlight(Exception):
    """Base for "not inserting a second audit". Never raised directly.

    Two subclasses, and the split is a security boundary rather than
    tidiness. The two partial unique indexes on `audits` mean different
    things and the caller must react differently:

      AuditInFlightMine   the CALLER already has one running. Carries the
                          row, because redirecting them to their own audit
                          is exactly what they want.
      AuditInFlightOther  SOMEONE ELSE is auditing this repository.
                          Carries NOTHING -- not the row, not the id, not
                          the requester -- because a visitor audit is
                          visible only to its requester, and the id alone
                          would be a working URL to someone else's result.

    Before the split there was one exception carrying the row, and the
    route redirected to it unconditionally. Under per-requester visibility
    that hands visitor B a link to visitor A's audit: a leak created by
    our own in-flight rule, with no attacker involved.
    """


class AuditInFlightMine(AuditInFlight):
    def __init__(self, existing: dict):
        self.existing = existing
        super().__init__(
            f"this requester already has an audit in flight for "
            f"{existing['owner']}/{existing['repo']}"
        )


class AuditInFlightOther(AuditInFlight):
    """Deliberately carries no attributes. See AuditInFlight."""

    def __init__(self, owner: str, repo: str):
        self.owner = owner
        self.repo = repo
        super().__init__(f"another audit is already in flight for {owner}/{repo}")


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
    violated = None
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
    except errors.UniqueViolation as exc:
        # WHICH index fired decides what the caller may be told, so the
        # constraint name is read rather than guessed. Postgres puts it in
        # diag.constraint_name; falling back to the message keeps this
        # working if that is ever empty.
        violated = getattr(exc.diag, "constraint_name", None) or str(exc)

    # A SEPARATE connection, and the reason is not stylistic. psycopg
    # wraps `pool.connection()` in a transaction, and a constraint
    # violation aborts it: every further statement on that connection
    # fails with InFailedSqlTransaction until it unwinds. The recovery
    # read therefore cannot share the block that raised — it has to
    # happen after the rollback, on a connection that is not poisoned.
    # The per-repo index fired: someone else is auditing this repository.
    # Nothing about their audit is looked up, let alone returned -- see
    # AuditInFlightOther. This branch comes FIRST because it is the one
    # that must not leak, so it cannot be reached by falling through.
    if "per_repo" in violated:
        async with pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    "SELECT requested_by FROM audits WHERE owner = %s AND repo = %s "
                    "AND status IN ('queued', 'running') ORDER BY created_at DESC LIMIT 1",
                    (owner, repo),
                )
                row = await cur.fetchone()
        if row is None:
            # Finished between the violation and this read. Retry once: the
            # constraint that blocked us no longer applies.
            return await request_audit(
                pool, owner=owner, repo=repo, requested_by=requested_by, private=private,
            )
        if row["requested_by"] == requested_by:
            # Their own, reached via the per-repo index because they asked
            # for the same repository twice. RAISE rather than return it:
            # a value from request_audit means "I created this row", and
            # handing back an existing one would make the caller enqueue
            # against an audit that already has a job.
            existing = await _in_flight_for(pool, owner, repo, requested_by=requested_by)
            raise AuditInFlightMine(existing)
        raise AuditInFlightOther(owner, repo)

    # The per-requester index fired: the caller's own audit, on any repo.
    existing = await _in_flight_for(pool, requested_by=requested_by)
    if existing is None:
        return await request_audit(
            pool, owner=owner, repo=repo, requested_by=requested_by, private=private,
        )
    raise AuditInFlightMine(existing)


async def _in_flight_for(
    pool: AsyncConnectionPool, owner: str | None = None, repo: str | None = None,
    *, requested_by: str | None = None,
) -> dict | None:
    """The caller's own in-flight audit, by repo or by requester.

    Only ever used to build AuditInFlightMine, i.e. only ever to return a
    row to the person who created it.
    """
    where = "status IN ('queued', 'running')"
    params: list[Any] = []
    if requested_by is not None:
        where += " AND requested_by = %s"
        params.append(requested_by)
    if owner is not None:
        where += " AND owner = %s AND repo = %s"
        params.extend([owner, repo])
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT {_COLUMNS} FROM audits WHERE {where} "
                "ORDER BY created_at DESC LIMIT 1",
                params,
            )
            return await cur.fetchone()


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
    report_json: dict | None = None,
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
                   estimated_cost_usd = %s, duration_s = %s, finished_at = now(),
                   report_json = %s
            WHERE id = %s
            """,
            (status, report_markdown, exit_code, error, tokens_in, tokens_out,
             estimated_cost_usd, duration_s,
             Jsonb(report_json) if report_json is not None else None, audit_id),
        )


DEAD_LETTER_REASON = (
    "The audit was interrupted and could not be completed. Please try again."
)


async def fail_audit_for_dead_letter(pool: AsyncConnectionPool, dead_letter) -> bool:
    """Move an audit to 'failed' when its job is dead-lettered.

    THE HOLE THIS CLOSES. handle_repo_audit sets 'running' and is the only
    writer that ever sets a terminal status. A worker that dies leaves the
    row 'running'; if the job is then dead-lettered -- lease expiry past
    max_delivery_attempts, or nack() exhausting them -- nothing ever
    finishes it.

    That is not merely an untidy row. audits_one_in_flight_per_repo is a
    partial unique index over ('queued','running'), so a permanently
    running row means THAT REPOSITORY CAN NEVER BE AUDITED AGAIN. One
    dead worker removes a repo from service for good.

    Called from BOTH producers of a DeadLetter, because they are different
    paths and only one of them runs in the worker:

      api/main.py  _on_sweep      the reaper, for a worker that never
                                  called nack() -- i.e. one that died
      worker       process_job    nack() exhausting max_attempts

    Guarded on the current status rather than blindly updating. A
    redelivery can dead-letter a job whose audit already finished, and
    rewriting a 'done' row with a report into 'failed' would destroy the
    result the user is looking at. Returns whether it changed anything, so
    a caller can log the difference between "recovered a stuck audit" and
    "nothing to do".

    Tolerant of payloads that are not audits and of audit payloads with no
    audit_id: this runs inside the reaper's sweep loop, and a sweep that
    raises stops reaping every other expired lease behind it.
    """
    if getattr(dead_letter, "type", None) != "repo_audit":
        return False
    audit_id = (dead_letter.payload or {}).get("audit_id")
    if not audit_id:
        logger.warning("repo_audit dead letter %s has no audit_id in its payload",
                       getattr(dead_letter, "id", "?"))
        return False

    reason = dead_letter.failed_reason or "unknown"
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            UPDATE audits
               SET status = 'failed',
                   error = %s,
                   finished_at = now()
             WHERE id = %s AND status IN ('queued', 'running')
            """,
            (f"{DEAD_LETTER_REASON} (job dead-lettered after {dead_letter.attempts} "
             f"attempt(s): {reason})", audit_id),
        )
        changed = cur.rowcount > 0

    if changed:
        logger.warning("audit %s marked failed: its job was dead-lettered", audit_id)
    return changed


async def latest_per_repo(
    pool: AsyncConnectionPool, *, requested_by: str | None = None,
) -> dict[tuple[str, str], dict]:
    """The newest audit for every repo, keyed by (owner, repo).

    SCOPED TO ONE REQUESTER unless `requested_by` is None. Unscoped was
    the default and it was a disclosure: the repositories page renders this
    row's audit id as a link and its status as text, so every viewer saw
    whoever had audited that repo last. An audit is visible only to the
    person who asked for it (or to an operator) — see _may_read_audit in
    routes/dashboard.py — and a page that shows it anyway is the same leak
    reached through the page instead of the URL.

    requested_by=None is kept for the operator's own view and for callers
    that are not rendering to a visitor. It is a keyword argument
    specifically so that an unscoped read is something a caller has to ask
    for by name.

    One query with DISTINCT ON rather than one per row: the page already
    costs a GitHub call per repo for the visibility gate and does not need
    a database round trip per row on top.
    """
    where = ""
    params: list[Any] = []
    if requested_by is not None:
        # Case-insensitive, like every other comparison against a GitHub
        # login in this codebase — the allow-list, can_access_repo's cache
        # key and may_trigger_audit all lower-case first, and a row this
        # query missed would silently show as "never audited".
        where = "WHERE lower(requested_by) = lower(%s) "
        params.append(requested_by)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT DISTINCT ON (owner, repo) {_COLUMNS} FROM audits "
                f"{where}ORDER BY owner, repo, created_at DESC",
                params,
            )
            return {(row["owner"], row["repo"]): row for row in await cur.fetchall()}


async def in_flight_for_requester(
    pool: AsyncConnectionPool, requested_by: str,
) -> dict | None:
    """This person's own queued-or-running audit, if they have one.

    audits_one_in_flight_per_user (migration 010) allows exactly one, so
    the repositories page needs to know about it for EVERY row, not just
    the row it happens to be on: without this, every other repository
    offers a live "Run audit" button whose click is silently redirected to
    the audit already running somewhere else. The button is not dangerous
    — the index holds and no second job is queued — it just does something
    other than what it says.

    A thin wrapper over _in_flight_for, named for what the page is asking
    rather than leaving the page to pass the right combination of optional
    arguments.
    """
    return await _in_flight_for(pool, requested_by=requested_by)


async def audit_stats(
    pool: AsyncConnectionPool, *, requested_by: str,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Audit count, last audit and total audit cost per repo, for ONE
    requester -- the Repositories page's Activity columns.

    requested_by is required, not optional as in latest_per_repo. An audit
    is visible only to the person who asked for it, so an unscoped total
    would disclose that somebody else audited a repository, when, and what
    it cost them. There is no caller for which the unscoped sum is right.

    Every status counts, as a row on the page does: a failed audit still
    happened, and a timed-out one still spent money.
    """
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT owner, repo, count(*) AS audit_count,
                       max(created_at) AS last_audited,
                       coalesce(sum(estimated_cost_usd), 0) AS total_cost
                FROM audits WHERE lower(requested_by) = lower(%s)
                GROUP BY owner, repo
                """,
                (requested_by,),
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
