"""Worker process: poll -> claim -> heartbeat loop -> fetch installation
token -> post comment -> ack/nack.

Ported from Reliqueue's worker/main.py. worker_id = socket.gethostname()
— stable per-container under Docker Compose, and exactly what a chaos
test needs to find and kill a specific replica by the hostname recorded
in a job's `leased_by` column, without ever hardcoding a container name.

Heartbeat / lease loss: while a job is being processed, a concurrent
heartbeat task calls extend_lease() every heartbeat_interval_seconds. If
extend_lease() ever returns False, the lease has already been reassigned
(typically: this worker stalled long enough for the reaper to reclaim it,
then woke back up) — an `abandoned` event is set, and the handler bails
out without calling ack() or nack(). Not strictly required for
correctness (ack()/nack() are already no-ops for a worker that doesn't
hold the current lease), but it stops a zombie worker doing pointless
further work on a job it no longer owns.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import socket
import time

import requests
from prometheus_client import Counter, Histogram, start_http_server

from codeguard.config import Settings, get_settings
from codeguard.diff.ingest import ingest_pr_diff
from codeguard.github.auth import get_installation_token
from codeguard.github.comments import post_comment
from codeguard.github.errors import extract_retry_after
from codeguard.github.notifications import notify_dead_letter
from codeguard.github.repo_config import load_repo_config
from codeguard.queue.db import bootstrap_schema, create_pool
from codeguard.queue.models import Job
from codeguard.queue.queue import ack, claim_batch, extend_lease, nack

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("codeguard.worker")

WORKER_ID = socket.gethostname()

CONNECTED_COMMENT = "CodeGuard v2 connected — review pipeline coming soon."

JOBS_CLAIMED = Counter("codeguard_worker_jobs_claimed_total", "Jobs claimed by this worker (one per delivery attempt)")
JOBS_COMPLETED = Counter("codeguard_worker_jobs_completed_total", "Jobs successfully acked by this worker")
JOBS_FAILED = Counter("codeguard_worker_jobs_failed_total", "Jobs that raised during processing and were nacked")
JOB_PROCESSING_SECONDS = Histogram(
    "codeguard_worker_job_processing_seconds",
    "Wall time from claim to ack/nack/abandon", ["type"],
)
HEARTBEATS = Counter("codeguard_worker_heartbeats_total", "Successful lease renewals sent")
LEASES_LOST = Counter("codeguard_worker_leases_lost_total", "Heartbeats that found the lease already reassigned")
LEASE_RECOVERY_SECONDS = Histogram(
    "codeguard_worker_lease_recovery_seconds",
    "Time from the reaper recovering an expired lease to the job being claimed again",
)
COMMENTS_POSTED = Counter("codeguard_worker_comments_posted_total", "Comments successfully posted to a PR")
COMMENTS_FAILED = Counter("codeguard_worker_comments_failed_total", "Comment-post attempts that raised (token fetch or post itself)")


class RateLimited(Exception):
    """Raised by a handler when a GitHub API call comes back rate-limited,
    carrying the delay GitHub itself suggested (Retry-After /
    X-RateLimit-Reset) so process_job() can pass it to nack() as an
    explicit delay instead of trusting generic exponential backoff to
    happen to be long enough.
    """
    def __init__(self, retry_after: float):
        super().__init__(f"rate limited, retry after {retry_after:.1f}s")
        self.retry_after = retry_after


def _validate_config(settings: Settings) -> None:
    if settings.heartbeat_interval_seconds >= settings.lease_seconds:
        raise ValueError(
            f"heartbeat_interval_seconds ({settings.heartbeat_interval_seconds}) must be "
            f"comfortably less than lease_seconds ({settings.lease_seconds}) — otherwise a "
            "long-running job can lose its lease before the first heartbeat ever renews it."
        )


async def _comment_already_posted(pool, job: Job) -> bool:
    """Idempotency guard for the GitHub side effect itself — the queue
    guarantees at-least-once *delivery*, not at-most-once *side effect*.
    Without this, a worker that posts successfully and then crashes
    before ack() causes a redelivery that posts the same comment again
    (observed directly during Phase 2 verification: a killed worker's
    already-successful post, followed by the recovering worker's second
    post for the same job). Mirrors Reliqueue's sent_emails pattern.

    Deliberately a plain read here, not a claiming INSERT — the insert
    happens only in _record_comment_posted(), after a *confirmed*
    successful post (see handle_pull_request_review). Recording before
    attempting the post would be worse than the bug this fixes: a post
    that then failed would be permanently, silently skipped on every
    future retry instead of occasionally duplicated. The narrower
    remaining race — two concurrent deliveries of the same job both
    passing this check before either records — can't happen in
    practice, because claim_batch()'s lease already serializes access
    to a given job_id; the only way to reach a second delivery at all
    is sequential (after the first lease expires), never concurrent.
    """
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM posted_comments WHERE idempotency_key = %s",
                (job.idempotency_key,),
            )
            return (await cur.fetchone()) is not None


async def _record_comment_posted(pool, job: Job) -> None:
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO posted_comments (idempotency_key, job_id)
                VALUES (%s, %s)
                ON CONFLICT (idempotency_key) DO NOTHING
                """,
                (job.idempotency_key, job.id),
            )


def _log_diff_ingestion_result(pr_number: int, repo_config, result) -> None:
    """The Phase 3 done-when deliverable: a logged, structured,
    filtered, budgeted representation of the PR — not posted anywhere
    yet, just visible for verification. Later phases will feed this
    into the actual review pipeline instead of just logging it.
    """
    logger.info(
        "diff ingestion pr=%s: files_seen=%d files_reviewed=%d files_filtered=%d hunks=%d "
        "budget_exceeded=%s fix_threshold=%s enable_ai_aware=%s",
        pr_number, result.files_seen, len(result.files_reviewed), len(result.files_filtered),
        len(result.hunks), result.budget_exceeded, repo_config.fix_threshold.name, repo_config.enable_ai_aware,
    )
    for path in result.files_reviewed:
        logger.info("  reviewed: %s", path)
    for f in result.files_filtered:
        logger.info("  filtered: %s (%s)", f.path, f.reason)
    for h in result.hunks:
        logger.info("  hunk: %s:%d-%d [%s, %d chars]", h.path, h.start_line, h.end_line, h.content_hash[:12], len(h.content))


async def handle_pull_request_review(job: Job, pool, abandoned: asyncio.Event) -> bool:
    """Fetches this job's own installation token (never cached across
    jobs — see codeguard/github/auth.py), reused for both diff ingestion
    and the comment post below. Phase 3 adds real diff ingestion
    (fetch/filter/budget/log); the actual review pipeline and what gets
    posted based on it land in later phases — this still just posts the
    hardcoded "connected" comment regardless of what ingestion found.
    """
    payload = job.payload
    installation_id = payload["installation_id"]
    owner = payload["owner"]
    repo = payload["repo"]
    pr_number = payload["pr_number"]
    head_sha = payload.get("head_sha")
    base_ref = payload.get("base_ref")

    if await _comment_already_posted(pool, job):
        logger.info("job %s: comment already posted by a previous delivery attempt, skipping", job.id)
        return True

    token = get_installation_token(installation_id)

    if head_sha and base_ref:
        try:
            settings = get_settings()
            repo_config = load_repo_config(token, owner, repo, base_ref)
            result = ingest_pr_diff(token, owner, repo, pr_number, head_sha, repo_config, settings)
            _log_diff_ingestion_result(pr_number, repo_config, result)
        except Exception:
            # Best-effort for now — a diff-ingestion failure shouldn't
            # block the comment below from posting. Once later phases
            # make the review depend on this, that changes.
            logger.exception("diff ingestion failed for pr=%s — continuing without it", pr_number)

    try:
        post_comment(token, owner, repo, pr_number, CONNECTED_COMMENT)
    except requests.HTTPError as exc:
        COMMENTS_FAILED.inc()
        retry_after = extract_retry_after(exc.response) if exc.response is not None else None
        if retry_after is not None:
            raise RateLimited(retry_after) from exc
        raise

    await _record_comment_posted(pool, job)
    COMMENTS_POSTED.inc()
    return True


HANDLERS = {
    "pull_request_review": handle_pull_request_review,
}


async def heartbeat_loop(pool, job: Job, abandoned: asyncio.Event, settings: Settings) -> None:
    while True:
        await asyncio.sleep(settings.heartbeat_interval_seconds)
        ok = await extend_lease(pool, job_id=job.id, worker_id=WORKER_ID, lease_seconds=settings.lease_seconds)
        if not ok:
            LEASES_LOST.inc()
            logger.warning("lease for job %s no longer held by %s — abandoning processing", job.id, WORKER_ID)
            abandoned.set()
            return
        HEARTBEATS.inc()


async def process_job(pool, job: Job, settings: Settings) -> None:
    logger.info("processing job %s (%s), attempt %d", job.id, job.type, job.attempts)
    abandoned = asyncio.Event()
    hb_task = asyncio.create_task(heartbeat_loop(pool, job, abandoned, settings))
    start = time.perf_counter()
    try:
        handler = HANDLERS.get(job.type)
        if handler is None:
            raise ValueError(f"no handler registered for type={job.type!r}")
        completed = await handler(job, pool, abandoned)
    except Exception as exc:
        JOBS_FAILED.inc()
        explicit_delay = exc.retry_after if isinstance(exc, RateLimited) else None
        dead_letter = await nack(
            pool, job_id=job.id, worker_id=WORKER_ID, reason=str(exc),
            max_attempts=settings.max_delivery_attempts,
            base_backoff=settings.base_backoff_seconds,
            max_delay=settings.max_backoff_delay_seconds,
            explicit_delay=explicit_delay,
        )
        logger.warning("job %s failed: %s", job.id, exc)
        if dead_letter is not None:
            await notify_dead_letter(dead_letter)
    else:
        if abandoned.is_set() or not completed:
            logger.info("job %s abandoned mid-processing (lease lost) — not acking", job.id)
        else:
            ok = await ack(pool, job_id=job.id, worker_id=WORKER_ID)
            if ok:
                JOBS_COMPLETED.inc()
                logger.info("job %s completed", job.id)
            else:
                logger.warning("job %s: ack failed despite not detecting abandonment "
                               "(lease must have been lost right at the very end)", job.id)
    finally:
        hb_task.cancel()
        try:
            await hb_task
        except asyncio.CancelledError:
            pass
        JOB_PROCESSING_SECONDS.labels(type=job.type).observe(time.perf_counter() - start)


async def main() -> None:
    settings = get_settings()
    _validate_config(settings)
    logger.info(
        "starting worker %s (lease=%ss, heartbeat=%ss, batch=%d, max_attempts=%d)",
        WORKER_ID, settings.lease_seconds, settings.heartbeat_interval_seconds,
        settings.queue_batch_size, settings.max_delivery_attempts,
    )
    start_http_server(settings.worker_metrics_port)
    logger.info("metrics exposed on :%d/metrics", settings.worker_metrics_port)

    pool = await create_pool(settings)
    # Idempotent (CREATE ... IF NOT EXISTS) — defensive against a startup
    # race where this worker's connection wins over api's own lifespan
    # bootstrap; safe to run from both processes.
    await bootstrap_schema(pool)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass  # Windows: no add_signal_handler; fine for local dev, containers run Linux.

    try:
        while not stop.is_set():
            jobs = await claim_batch(
                pool, worker_id=WORKER_ID,
                batch_size=settings.queue_batch_size,
                lease_seconds=settings.lease_seconds,
            )
            if not jobs:
                await asyncio.sleep(settings.queue_poll_interval_seconds)
                continue

            JOBS_CLAIMED.inc(len(jobs))
            for job in jobs:
                if job.lease_recovery_seconds is not None:
                    LEASE_RECOVERY_SECONDS.observe(job.lease_recovery_seconds)
                    logger.info("job %s claimed %.3fs after its lease was recovered by the reaper",
                                job.id, job.lease_recovery_seconds)
            await asyncio.gather(*(process_job(pool, job, settings) for job in jobs))
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
