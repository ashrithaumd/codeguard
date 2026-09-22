"""Persists one `reviews` row per completed review — the per-review
record the pipeline computes and then throws away (see
migrations/006_reviews.sql for the full rationale and for the escaping
requirement that applies to everything stored here).

Best-effort by design: record_review() never raises. This row is
observability, not correctness. A review that was successfully posted to
GitHub must not be retried — and must not fail its ack — because a stats
insert failed. Same discipline llm_call.py applies to LangSmith tracing:
observability is never load-bearing.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from psycopg_pool import AsyncConnectionPool

from codeguard.tools.models import Finding

logger = logging.getLogger(__name__)

# Trust classification, derived from Finding.source_tool. See the schema
# comment in migrations/006_reviews.sql for why "deterministic" and
# "unverified" are kept apart, and for what `unverified` does and does not
# mean. Anything not listed here falls to `unverified` (see _bucket).
_VERDICT_CONFIRMED_TOOLS = frozenset({"security", "ai_aware"})
_GENERATIVE_TOOLS = frozenset({"quality-agent", "test-agent"})
_DETERMINISTIC_TOOLS = frozenset({"ruff", "osv", "eval-hygiene"})

BUCKETS = ("verdict_confirmed", "generative", "deterministic", "unverified")


def _bucket(source_tool: str) -> str:
    """An unrecognised source_tool is `unverified`, not a new bucket and
    not dropped: claiming verification we cannot prove is the worse
    error, and dropping it would break the partition the schema's CHECK
    constraint asserts.
    """
    if source_tool in _VERDICT_CONFIRMED_TOOLS:
        return "verdict_confirmed"
    if source_tool in _GENERATIVE_TOOLS:
        return "generative"
    if source_tool in _DETERMINISTIC_TOOLS:
        return "deterministic"
    return "unverified"


def classify_findings(findings: list[Finding]) -> dict[str, int]:
    """Partitions findings across BUCKETS. Every finding lands in exactly
    one bucket, so the counts always sum to len(findings) by
    construction — the schema's reviews_bucket_sum CHECK is a guard
    against a future writer that stops doing this, not a runtime risk
    here.
    """
    counts = dict.fromkeys(BUCKETS, 0)
    for f in findings:
        counts[_bucket(f.source_tool)] += 1
    return counts


def _dump(models: list[Any]) -> str:
    """Pydantic models -> JSON text for a JSONB column, matching
    hunk_cache.py's convention. NamedTuples (VerdictCallFailure) and
    plain dicts (NodeLatency) are handled too, since node_latencies and
    verdict_call_failures are not Pydantic models.
    """
    out = []
    for m in models:
        if hasattr(m, "model_dump"):
            out.append(m.model_dump(mode="json"))
        elif hasattr(m, "_asdict"):
            out.append(m._asdict())
        else:
            out.append(m)
    return json.dumps(out)


async def record_review(
    pool: AsyncConnectionPool,
    *,
    job_id: UUID,
    owner: str,
    repo: str,
    pr_number: int,
    head_sha: str,
    action: str,
    private: bool,
    summary_body: str,
    check_conclusion: str | None,
    gate_threshold: str,
    fix_threshold: str,
    files_seen: int,
    files_reviewed: int,
    findings: list[Finding],
    dismissed: list[Any],
    inline_count: int,
    fix_suggestions: list[Any],
    budget_exceeded: bool,
    filtered_files: list[Any],
    tokens_in: int,
    tokens_out: int,
    estimated_cost_usd: float,
    duration_s: float,
    node_latencies: list[Any],
    verdict_call_failures: list[Any],
) -> bool:
    """Returns True if a row was written, False on any failure or when
    the row already existed. Never raises.

    ON CONFLICT DO NOTHING on job_id: handle_pull_request_review's own
    _review_already_posted guard should already prevent a second attempt
    for the same delivery, but the queue is at-least-once and this makes
    the write idempotent by construction rather than by relying on that
    guard holding.
    """
    counts = classify_findings(findings)
    try:
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO reviews (
                    job_id, owner, repo, pr_number, head_sha, action, private,
                    summary_body, check_conclusion, gate_threshold, fix_threshold,
                    files_seen, files_reviewed, findings_total,
                    findings_verdict_confirmed, findings_generative,
                    findings_deterministic, findings_unverified,
                    dismissed_count, inline_count, fix_suggestion_count,
                    budget_exceeded, filtered_files_json,
                    tokens_in, tokens_out, estimated_cost_usd, duration_s,
                    node_latencies_json,
                    findings_json, dismissed_json, fix_suggestions_json,
                    verdict_call_failures_json
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s, %s, %s,
                    %s,
                    %s, %s, %s,
                    %s
                )
                ON CONFLICT (job_id) DO NOTHING
                """,
                (
                    job_id, owner, repo, pr_number, head_sha, action, private,
                    summary_body, check_conclusion, gate_threshold, fix_threshold,
                    files_seen, files_reviewed, len(findings),
                    counts["verdict_confirmed"], counts["generative"],
                    counts["deterministic"], counts["unverified"],
                    len(dismissed), inline_count, len(fix_suggestions),
                    budget_exceeded, _dump(filtered_files),
                    tokens_in, tokens_out, estimated_cost_usd, duration_s,
                    _dump(node_latencies),
                    _dump(findings), _dump(dismissed), _dump(fix_suggestions),
                    _dump(verdict_call_failures),
                ),
            )
        return True
    except Exception:
        # Deliberately broad and deliberately swallowed — see the module
        # docstring. The review is already posted to GitHub by the time
        # this runs; letting a stats failure propagate would fail the
        # handler, skip the ack, and cause the whole review to be
        # redelivered and re-posted.
        logger.warning("failed to record review row for job %s", job_id, exc_info=True)
        return False
