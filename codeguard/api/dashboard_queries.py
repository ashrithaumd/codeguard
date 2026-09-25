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

from datetime import date, timedelta
from typing import Any
from urllib.parse import urlencode
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
    limit: int = 50, offset: int = 0, filters: "Filters | None" = None,
) -> list[dict]:
    params: list[Any] = []
    where = _where(principal_repos, params, filters)
    params.extend([limit, offset])
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT {_LIST_COLUMNS} FROM reviews WHERE {where} "
                f"ORDER BY created_at DESC LIMIT %s OFFSET %s",
                params,
            )
            return await cur.fetchall()


async def count_reviews(
    pool: AsyncConnectionPool, *, principal_repos: list[tuple[str, str]],
    filters: "Filters | None" = None,
) -> int:
    params: list[Any] = []
    where = _where(principal_repos, params, filters)
    # Named, not positional: queue/db.py's _configure_connection sets
    # row_factory = dict_row on every pooled connection, so row[0] is a
    # KeyError rather than the first column.
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(f"SELECT count(*) AS n FROM reviews WHERE {where}", params)
            row = await cur.fetchone()
            return row["n"] if row else 0


async def list_repos(
    pool: AsyncConnectionPool, *, principal_repos: list[tuple[str, str]],
    filters: "Filters | None" = None,
) -> list[dict]:
    """One row per repo for the index's filter, with enough to be worth
    showing on its own: how many reviews, what they cost, when last seen.
    """
    params: list[Any] = []
    where = _where(principal_repos, params, filters)
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


async def distinct_repos(pool: AsyncConnectionPool) -> list[tuple[str, str, bool]]:
    """Every (owner, repo, private) that has a review row.

    The repositories page's fallback when GitHub cannot be asked which
    repos the App is installed on. Strictly narrower than that list — it
    can only contain repos that have already been reviewed — so falling
    back to it can never surface a repository the installed-list would
    not have, which is what makes it safe to show without a live
    installation check.

    `private` is the strictest value across the repo's rows, matching
    repo_detail's rule: one private row gates the whole repo.
    """
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT owner, repo, bool_or(private) AS private FROM reviews "
                "GROUP BY owner, repo"
            )
            return [(row["owner"], row["repo"], row["private"]) for row in await cur.fetchall()]


async def totals(
    pool: AsyncConnectionPool, *, principal_repos: list[tuple[str, str]],
    filters: "Filters | None" = None,
) -> dict:
    """Aggregates over EVERY review the visitor can see, not just the
    page they are looking at.

    The KPI strip used to sum the current page, so paginating changed
    the headline numbers and "Cost" meant "cost of fifty arbitrary
    reviews" — a number that answers no question anyone has. Same
    visibility filter as the listing, so the totals never describe rows
    the listing will not show.
    """
    params: list[Any] = []
    where = _where(principal_repos, params, filters)
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"""
                SELECT count(*)                                  AS reviews,
                       count(DISTINCT (owner, repo))             AS repos,
                       coalesce(sum(findings_total), 0)          AS findings,
                       coalesce(sum(fix_suggestion_count), 0)    AS fixes,
                       coalesce(sum(estimated_cost_usd), 0)      AS cost,
                       coalesce(sum(findings_verdict_confirmed), 0) AS verdict_confirmed,
                       coalesce(sum(findings_generative), 0)     AS generative,
                       coalesce(sum(findings_deterministic), 0)  AS deterministic,
                       coalesce(sum(findings_unverified), 0)     AS unverified,
                       count(*) FILTER (WHERE check_conclusion = 'failure') AS blocked
                FROM reviews WHERE {where}
                """,
                params,
            )
            return await cur.fetchone() or {}


async def pr_history(
    pool: AsyncConnectionPool, *, owner: str, repo: str, pr_number: int,
) -> list[dict]:
    """Every review of ONE pull request, newest first.

    This is the only grouping in which consecutive reviews are
    comparable. A repo-wide series mixes pull requests, so two adjacent
    bars can be a 2-file PR and a 40-file PR and their difference means
    nothing — which is why the cost chart lives here and not on the repo
    page.
    """
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT {_LIST_COLUMNS} FROM reviews "
                f"WHERE owner = %s AND repo = %s AND pr_number = %s "
                f"ORDER BY created_at DESC",
                (owner, repo, pr_number),
            )
            return await cur.fetchall()


async def pr_summaries(
    pool: AsyncConnectionPool, *, owner: str, repo: str,
) -> list[dict]:
    """One row per pull request in a repo, for the repo page's listing."""
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT pr_number,
                       count(*)                            AS review_count,
                       sum(estimated_cost_usd)             AS total_cost,
                       max(created_at)                     AS last_reviewed,
                       (array_agg(findings_total ORDER BY created_at DESC))[1]   AS latest_findings,
                       (array_agg(check_conclusion ORDER BY created_at DESC))[1] AS latest_conclusion,
                       bool_or(private)                    AS private
                FROM reviews WHERE owner = %s AND repo = %s
                GROUP BY pr_number
                ORDER BY max(created_at) DESC
                """,
                (owner, repo),
            )
            return await cur.fetchall()


# Severity names, in the order the UI offers them. Used to reject
# anything a query string invents before it reaches SQL — the value is
# compared inside a JSONB predicate, and an allow-list is how that stays
# a comparison rather than an injection point.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# check_conclusion values the gate filter accepts. "none" means the row
# has no Check Run at all, which is a real state (start_check_run can
# fail) and not the same as passing.
GATES = {"passed": "success", "blocked": "failure", "none": None}


class Filters:
    """The dashboard's query-string filters, parsed once and applied to
    every query on the page so the listing, the totals and the repo
    rollup can never describe different subsets.

    Everything is validated here rather than at the SQL call sites:
    `severity` is checked against SEVERITIES, `gate` against GATES, and
    the dates are parsed. An unrecognised value is dropped rather than
    rejected with an error — a stale bookmark should show the
    unfiltered page, not a stack trace.
    """

    def __init__(self, *, repo: str = "", severity: str = "", gate: str = "",
                 date_from: str = "", date_to: str = ""):
        self.repo = repo.strip()
        self.severity = severity.upper() if severity.upper() in SEVERITIES else ""
        self.gate = gate if gate in GATES else ""
        self.date_from = _parse_date(date_from)
        self.date_to = _parse_date(date_to)

    @property
    def active(self) -> bool:
        return bool(self.repo or self.severity or self.gate or self.date_from or self.date_to)

    def query_string(self, **overrides) -> str:
        """The filters as a query string, for building links that keep
        the current view. Overrides let a template add or clear one
        without reassembling the rest by hand.
        """
        parts = {
            "repo": self.repo, "severity": self.severity, "gate": self.gate,
            "from": self.date_from.isoformat() if self.date_from else "",
            "to": self.date_to.isoformat() if self.date_to else "",
        }
        parts.update({k: ("" if v is None else str(v)) for k, v in overrides.items()})
        return urlencode({k: v for k, v in parts.items() if v})

    def _sql(self, params: list[Any]) -> str:
        """The WHERE fragments, ANDed. Every value is a parameter."""
        clauses: list[str] = []
        if self.repo:
            owner, _, name = self.repo.partition("/")
            if name:
                clauses.append("(owner = %s AND repo = %s)")
                params.extend([owner, name])
            else:
                clauses.append("repo = %s")
                params.append(self.repo)
        if self.severity:
            # A review matches if ANY of its findings is at that
            # severity. Reviews store per-trust-bucket counts but no
            # severity counts, so this reads the detail JSONB — the only
            # place severity is recorded.
            clauses.append(
                "EXISTS (SELECT 1 FROM jsonb_array_elements(findings_json) AS f "
                "WHERE f->>'severity' = %s)"
            )
            params.append(self.severity)
        if self.gate:
            conclusion = GATES[self.gate]
            if conclusion is None:
                clauses.append("check_conclusion IS NULL")
            else:
                clauses.append("check_conclusion = %s")
                params.append(conclusion)
        if self.date_from:
            clauses.append("created_at >= %s")
            params.append(self.date_from)
        if self.date_to:
            # Inclusive of the whole end day: a reader picking the same
            # date for both ends means "that day", not "the instant
            # midnight began".
            clauses.append("created_at < %s")
            params.append(self.date_to + timedelta(days=1))
        return " AND ".join(clauses)


def _parse_date(value: str):
    try:
        return date.fromisoformat(value.strip()) if value else None
    except ValueError:
        return None


def _where(principal_repos, params: list[Any], filters: "Filters | None") -> str:
    """Visibility AND the page's filters. Visibility is never optional,
    so it is composed here rather than left to each call site.
    """
    clause = _visibility_clause(principal_repos, params)
    extra = filters._sql(params) if filters is not None else ""
    return f"({clause}) AND ({extra})" if extra else clause


async def search_index(
    pool: AsyncConnectionPool, *, principal_repos: list[tuple[str, str]], limit: int = 400,
) -> dict:
    """Everything the quick-jump palette can match on, in one round trip.

    Built server-side and sent whole rather than queried per keystroke:
    the dataset is one row per repo and one per pull request, so it is
    small, and a local match is instant where a request per keystroke is
    not. Visibility-filtered like every other query here, so the palette
    can never surface a private repo's name to someone who cannot open
    it.
    """
    repo_params: list[Any] = []
    repo_where = _visibility_clause(principal_repos, repo_params)
    pr_params: list[Any] = []
    pr_where = _visibility_clause(principal_repos, pr_params)
    file_params: list[Any] = []
    file_where = _visibility_clause(principal_repos, file_params)
    file_params.append(limit)

    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT DISTINCT owner, repo FROM reviews WHERE {repo_where} ORDER BY owner, repo",
                repo_params,
            )
            repos = await cur.fetchall()

            await cur.execute(
                f"""
                SELECT owner, repo, pr_number,
                       (array_agg(pr_title ORDER BY created_at DESC))[1] AS pr_title,
                       max(created_at) AS last_reviewed
                FROM reviews WHERE {pr_where}
                GROUP BY owner, repo, pr_number
                ORDER BY max(created_at) DESC
                """,
                pr_params,
            )
            pulls = await cur.fetchall()

            # File paths come out of the findings detail, which is where
            # the only record of which files a review touched lives.
            await cur.execute(
                f"""
                SELECT DISTINCT ON (path) f->>'file' AS path, owner, repo, pr_number, job_id
                FROM reviews, jsonb_array_elements(findings_json) AS f
                WHERE ({file_where}) AND f->>'file' <> '' AND f->>'file' <> '<pr>'
                ORDER BY path, created_at DESC
                LIMIT %s
                """,
                file_params,
            )
            files = await cur.fetchall()

    return {"repos": repos, "pulls": pulls, "files": files}
