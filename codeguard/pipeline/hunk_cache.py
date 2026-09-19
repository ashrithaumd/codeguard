"""DB-backed reuse for agent results, keyed by content_hash —
see migrations/004_hunk_findings.sql for the table shape and why
content_hash alone isn't the whole key.

Only worker/main.py calls the functions here. Nodes stay pure (no DB
access mid-graph, same as every other node in this package): worker/
main.py fetches hits into a plain dict, passes it into initial_state as
`hunk_cache_hits`, and after the graph runs, persists whatever fresh
results nodes queued in `final_state["cache_writes"]`.
"""

from __future__ import annotations

from psycopg.types.json import Jsonb
from psycopg_pool import AsyncConnectionPool

from codeguard.pipeline.models import CachedAgentResult, CacheKey, CacheWriteRecord, DismissedFinding
from codeguard.tools.models import Finding


async def fetch_cache_hits(
    pool: AsyncConnectionPool, owner: str, repo: str, keys: list[CacheKey],
) -> dict[CacheKey, CachedAgentResult]:
    """One query for every (path, content_hash, agent) this PR's
    agents are about to consider — not a per-key round trip, and not a
    full-repo table scan either (this repo's cache only grows without
    bound over the repo's life; filtering by the exact keys in play
    keeps this query's cost tied to the PR's size, not the repo's
    history).
    """
    if not keys:
        return {}

    values_sql = ", ".join(["(%s, %s, %s)"] * len(keys))
    params: list[str] = [owner, repo]
    for path, content_hash, agent in keys:
        params.extend([path, content_hash, agent])

    query = f"""
        SELECT path, content_hash, agent, findings_json, dismissed_json,
               tokens_in, tokens_out, estimated_cost_usd
        FROM hunk_findings
        WHERE owner = %s AND repo = %s
          AND (path, content_hash, agent) IN (VALUES {values_sql})
    """
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(query, params)
            rows = await cur.fetchall()

    hits: dict[CacheKey, CachedAgentResult] = {}
    for row in rows:
        hits[(row["path"], row["content_hash"], row["agent"])] = CachedAgentResult(
            findings=[Finding.model_validate(f) for f in row["findings_json"]],
            dismissed=[DismissedFinding.model_validate(d) for d in row["dismissed_json"]],
            tokens_in=row["tokens_in"],
            tokens_out=row["tokens_out"],
            estimated_cost_usd=row["estimated_cost_usd"],
        )
    return hits


async def write_cache_records(pool: AsyncConnectionPool, records: list[CacheWriteRecord]) -> None:
    """ON CONFLICT DO NOTHING: content_hash-keyed content is immutable
    by construction (the hash IS the content), so a second write for
    the same key can only be a concurrent duplicate of the same
    result — nothing to reconcile, first write wins.
    """
    if not records:
        return
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            for r in records:
                await cur.execute(
                    """
                    INSERT INTO hunk_findings
                        (owner, repo, path, content_hash, agent, findings_json, dismissed_json,
                         tokens_in, tokens_out, estimated_cost_usd)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (owner, repo, path, content_hash, agent) DO NOTHING
                    """,
                    (
                        r.owner, r.repo, r.path, r.content_hash, r.agent,
                        Jsonb([f.model_dump(mode="json") for f in r.findings]),
                        Jsonb([d.model_dump(mode="json") for d in r.dismissed]),
                        r.tokens_in, r.tokens_out, r.estimated_cost_usd,
                    ),
                )
