"""Coverage for the per-review record (migrations/006_reviews.sql,
codeguard/pipeline/reviews.py).

Two kinds of test here, deliberately mixed in one module because they
protect the same invariant from opposite ends: the pure classification
tests pin the source_tool -> bucket mapping that the schema's
reviews_bucket_sum CHECK constraint cannot see, and the DB tests pin the
write itself (idempotency, never-raises, and no row on the handler's
early-return paths).
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

from codeguard.pipeline.reviews import BUCKETS, classify_findings, record_review
from codeguard.queue.queue import enqueue
from codeguard.severity import Severity
from codeguard.tools.models import Finding
from codeguard.worker.main import _record_review_posted, handle_pull_request_review


def _finding(source_tool: str, line: int = 1) -> Finding:
    return Finding.create(
        file="a.py", start_line=line, end_line=line, severity=Severity.MEDIUM,
        source_tool=source_tool, rule_id="R1", message="m",
    )


async def _row(pool, job_id):
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT * FROM reviews WHERE job_id = %s", (job_id,))
        return await cur.fetchone()


async def _record(pool, job_id, **overrides):
    """record_review with every required argument defaulted, so each test
    only states the part it cares about.
    """
    kwargs = dict(
        job_id=job_id, owner="o", repo="r", pr_number=7, head_sha="abc123",
        action="opened", summary_body="body", check_conclusion="success",
        gate_threshold="CRITICAL", fix_threshold="HIGH",
        files_seen=3, files_reviewed=2, findings=[], dismissed=[],
        inline_count=0, fix_suggestions=[], budget_exceeded=False,
        filtered_files=[], tokens_in=0, tokens_out=0, estimated_cost_usd=0.0,
        duration_s=0.0, node_latencies=[], verdict_call_failures=[],
    )
    kwargs.update(overrides)
    return await record_review(pool, **kwargs)


# --- classification (pure, no DB) ------------------------------------------

@pytest.mark.parametrize(
    ("source_tool", "expected"),
    [
        ("security", "verdict_confirmed"),
        ("ai_aware", "verdict_confirmed"),
        ("quality-agent", "generative"),
        ("test-agent", "generative"),
        ("ruff", "deterministic"),
        ("osv", "deterministic"),
        ("eval-hygiene", "deterministic"),
        ("bandit", "unverified"),
        ("semgrep", "unverified"),
    ],
)
def test_every_source_tool_the_pipeline_produces_maps_to_its_bucket(source_tool, expected):
    """The mapping the CHECK constraint cannot verify. These nine strings
    are every value assigned to Finding.source_tool anywhere in
    codeguard/ — a new tool added without a home here would silently be
    counted `unverified` (see the next test), which is safe but wrong.
    """
    counts = classify_findings([_finding(source_tool)])

    assert counts[expected] == 1
    assert sum(counts.values()) == 1


def test_an_unrecognised_source_tool_is_counted_unverified_not_dropped():
    """Conservative fallback: claiming verification we cannot prove is
    the worse error, and dropping it would break the partition the
    schema's CHECK constraint asserts.
    """
    counts = classify_findings([_finding("some-future-tool")])

    assert counts["unverified"] == 1
    assert sum(counts.values()) == 1


def test_buckets_always_partition_the_findings_exactly():
    findings = [
        _finding("security", 1), _finding("quality-agent", 2), _finding("ruff", 3),
        _finding("bandit", 4), _finding("unknown-tool", 5), _finding("ai_aware", 6),
    ]

    counts = classify_findings(findings)

    assert set(counts) == set(BUCKETS)
    assert sum(counts.values()) == len(findings)


# --- the write (real Postgres) ---------------------------------------------

async def test_record_review_writes_the_row_with_classified_counts(pool):
    job_id = uuid.uuid4()
    findings = [_finding("security", 1), _finding("bandit", 2), _finding("ruff", 3)]

    assert await _record(pool, job_id, findings=findings, inline_count=2, tokens_in=99) is True

    row = await _row(pool, job_id)
    assert row["owner"] == "o"
    assert row["pr_number"] == 7
    assert row["head_sha"] == "abc123"
    assert row["findings_total"] == 3
    assert row["findings_verdict_confirmed"] == 1
    assert row["findings_unverified"] == 1
    assert row["findings_deterministic"] == 1
    assert row["findings_generative"] == 0
    assert row["inline_count"] == 2
    assert row["tokens_in"] == 99
    assert row["check_conclusion"] == "success"


async def test_record_review_is_idempotent_on_job_id(pool):
    """ON CONFLICT DO NOTHING. The handler's own _review_already_posted
    guard should prevent a second attempt, but the queue is at-least-once
    and this must not raise or duplicate if that guard is ever bypassed.
    """
    job_id = uuid.uuid4()
    await _record(pool, job_id, summary_body="first")

    assert await _record(pool, job_id, summary_body="second") is True

    async with pool.connection() as conn:
        cur = await conn.execute("SELECT count(*) AS n FROM reviews WHERE job_id = %s", (job_id,))
        assert (await cur.fetchone())["n"] == 1
    row = await _row(pool, job_id)
    assert row["summary_body"] == "first"  # first write wins, not overwritten


async def test_a_failed_insert_returns_false_and_never_raises():
    """The review is already live on GitHub by the time this runs. A
    stats failure must not propagate, skip the ack, and cause a
    redelivery that posts the review a second time.
    """
    class BrokenPool:
        def connection(self):
            raise RuntimeError("pool is gone")

    assert await _record(BrokenPool(), uuid.uuid4()) is False


async def test_the_check_constraint_rejects_buckets_that_do_not_sum(pool):
    """Guards a future writer that stops partitioning. record_review
    cannot produce this, which is why it is inserted directly.
    """
    with pytest.raises(Exception) as exc:
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO reviews (
                    job_id, owner, repo, pr_number, head_sha, action, summary_body,
                    gate_threshold, fix_threshold, files_seen, files_reviewed,
                    findings_total, findings_verdict_confirmed, findings_generative,
                    findings_deterministic, findings_unverified,
                    dismissed_count, inline_count, fix_suggestion_count
                ) VALUES (%s, 'o', 'r', 1, 'sha', 'opened', 'b', 'CRITICAL', 'HIGH',
                          1, 1, 10, 1, 1, 1, 1, 0, 0, 0)
                """,
                (uuid.uuid4(),),
            )
    assert "reviews_bucket_sum" in str(exc.value)


async def test_an_early_return_writes_no_review_row(pool):
    """The already-posted guard returns before anything is reviewed or
    posted, so there is no review to record. Same setup as
    tests/queue/test_comment_idempotency.py: an invalid installation_id
    would raise a real HTTPError if the guard failed to skip.
    """
    job, _ = await enqueue(
        pool, type="pull_request_review",
        payload={"installation_id": 999999999, "owner": "x", "repo": "y",
                 "pr_number": 1, "action": "opened", "head_sha": "s", "base_ref": "main"},
        idempotency_key=f"reviews-early-return-{uuid.uuid4().hex[:8]}",
    )
    await _record_review_posted(pool, job)

    assert await handle_pull_request_review(job, pool, asyncio.Event()) is True

    assert await _row(pool, job.id) is None


async def test_a_job_missing_head_sha_writes_no_review_row(pool):
    """The second early return: nothing to review, so nothing to record."""
    job, _ = await enqueue(
        pool, type="pull_request_review",
        payload={"installation_id": 999999999, "owner": "x", "repo": "y",
                 "pr_number": 1, "action": "opened"},
        idempotency_key=f"reviews-no-sha-{uuid.uuid4().hex[:8]}",
    )

    assert await handle_pull_request_review(job, pool, asyncio.Event()) is True

    assert await _row(pool, job.id) is None
