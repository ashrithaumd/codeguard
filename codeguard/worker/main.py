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
from codeguard.github.base_tree import fetch_base_tree_python_files
from codeguard.github.check_summary import render_check_summary
from codeguard.github.checks import complete_check_run, start_check_run
from codeguard.github.errors import extract_retry_after
from codeguard.github.notifications import notify_dead_letter
from codeguard.github.repo_config import load_repo_config
from codeguard.github.reviews import fetch_review_comments, post_review
from codeguard.pipeline.feedback import FINGERPRINT_MARKER_RE, fetch_suppressed_fingerprints, fingerprint_marker, record_posted_finding_comments
from codeguard.pipeline.graph import review_graph
from codeguard.pipeline.hunk_cache import fetch_cache_hits, write_cache_records
from codeguard.pipeline.nodes import _exclude_suppressed, compute_cache_keys
from codeguard.pipeline.reviews import record_review
from codeguard.pipeline.state import ReviewState
from codeguard.queue.db import bootstrap_schema, create_pool
from codeguard.queue.models import Job
from codeguard.queue.queue import ack, claim_batch, extend_lease, nack
from codeguard.tools.osv_runner import check_dependency_updates
from codeguard.tools.run_all import run_tools_on_files

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("codeguard.worker")

WORKER_ID = socket.gethostname()

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
REVIEWS_POSTED = Counter("codeguard_worker_reviews_posted_total", "PR Reviews successfully posted (one call, inline comments + summary)")
REVIEWS_FAILED = Counter("codeguard_worker_reviews_failed_total", "Review-post attempts that raised (token fetch or post itself)")
CHECK_RUNS_COMPLETED = Counter(
    "codeguard_worker_check_runs_completed_total",
    "Check Runs successfully completed, by conclusion.", ["conclusion"],
)
CHECK_RUNS_FAILED = Counter(
    "codeguard_worker_check_runs_failed_total",
    "Check Run start/complete calls that raised (most commonly: App missing the checks:write permission).",
    ["stage"],  # stage: start | complete
)


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


async def _review_already_posted(pool, job: Job) -> bool:
    """Idempotency guard for the GitHub side effect itself — the queue
    guarantees at-least-once *delivery*, not at-most-once *side effect*.
    Without this, a worker that posts successfully and then crashes
    before ack() causes a redelivery that posts the same review again
    (observed directly during live verification, back when this guarded
    a single hardcoded comment — same guarantee, now guarding a whole PR
    Review instead). Table name (posted_comments) predates the move to
    posting reviews rather than individual comments; left as-is rather
    than a migration for a rename alone.

    Deliberately a plain read here, not a claiming INSERT — the insert
    happens only in _record_review_posted(), after a *confirmed*
    successful post. Recording before attempting the post would be
    worse than the bug this fixes: a post that then failed would be
    permanently, silently skipped on every future retry instead of
    occasionally duplicated. The narrower remaining race — two
    concurrent deliveries of the same job both passing this check
    before either records — can't happen in practice, because
    claim_batch()'s lease already serializes access to a given job_id;
    the only way to reach a second delivery at all is sequential (after
    the first lease expires), never concurrent.
    """
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT 1 FROM posted_comments WHERE idempotency_key = %s",
                (job.idempotency_key,),
            )
            return (await cur.fetchone()) is not None


async def _record_review_posted(pool, job: Job) -> None:
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
    """A logged, structured, filtered, budgeted representation of the
    PR's own diff ingestion step — separate from whatever the review
    pipeline itself later finds, purely for operational visibility.
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


def _log_findings(pr_number: int, findings) -> None:
    """Structured Findings with correct line numbers from the
    deterministic tool-runner step, logged for operational visibility —
    independent of whatever eventually gets posted inline via
    codeguard/tools/diff_position.py.
    """
    logger.info("tool findings pr=%s: %d finding(s) after changed-line filtering", pr_number, len(findings))
    for f in findings:
        logger.info("  finding: %s:%d-%d [%s/%s] %s: %s",
                     f.file, f.start_line, f.end_line, f.source_tool, f.severity.name, f.rule_id, f.message)


def _findings_to_review_comments(findings, fix_suggestions) -> list[dict]:
    """A finding with a matching FixSuggestion (by fingerprint) gets its
    suggestion-block appended under the finding's own comment body — one
    GitHub review comment, not two, and the suggestion never exists
    without the finding's own explanation right above it.

    Every body also carries a hidden fingerprint_marker() — invisible
    in GitHub's rendered markdown, recovered after posting (see
    _record_posted_finding_comments) so a later threaded reply can be
    traced back to the specific finding it's feedback about.
    """
    suggestions_by_fingerprint = {s.fingerprint: s for s in fix_suggestions}
    comments = []
    for f in findings:
        body = f"**[{f.source_tool} / {f.severity.name}] {f.rule_id}**\n\n{f.message}"
        suggestion = suggestions_by_fingerprint.get(f.fingerprint)
        if suggestion is not None:
            body = f"{body}\n\n{suggestion.suggestion_body}"
        body = f"{body}\n\n{fingerprint_marker(f.fingerprint)}"
        comments.append({"path": f.file, "line": f.start_line, "side": "RIGHT", "body": body})
    return comments


def _check_run_conclusion(all_findings, gate_threshold) -> tuple[str, str, list]:
    """The Check Run's conclusion and title, derived purely from max
    confirmed severity vs repo_config.gate_threshold — the same
    all_findings set (findings + repo_level_findings) fix_threshold
    already reads, so "would this have gotten a fix suggestion" and
    "does this block the check" are computed the same way, just against
    two independently-configurable thresholds (see RepoConfig.gate_threshold's
    own docstring for why they're separate).

    Returns the blocking findings themselves rather than a rendered
    summary: github/check_summary.py builds the body and needs this exact
    list, and computing it in two places is how the gate and the panel
    describing the gate start disagreeing.
    """
    blocking = [f for f in all_findings if f.severity >= gate_threshold]
    if not blocking:
        return "success", "No blocking findings", blocking
    return "failure", f"{len(blocking)} finding(s) at or above {gate_threshold.name}", blocking


async def handle_pull_request_review(job: Job, pool, abandoned: asyncio.Event) -> bool:
    """Fetches this job's own installation token (never cached across
    jobs — see codeguard/github/auth.py): diff ingestion -> deterministic
    tools -> the review graph (codeguard/pipeline/) -> one posted PR
    Review. A failure anywhere in ingestion/tooling/the graph propagates
    rather than being swallowed — the review is the deliverable, so a
    failure should nack and retry through the normal queue path, not
    silently post nothing.
    """
    payload = job.payload
    installation_id = payload["installation_id"]
    owner = payload["owner"]
    repo = payload["repo"]
    pr_number = payload["pr_number"]
    head_sha = payload.get("head_sha")
    base_ref = payload.get("base_ref")

    if await _review_already_posted(pool, job):
        logger.info("job %s: review already posted by a previous delivery attempt, skipping", job.id)
        return True

    if not (head_sha and base_ref):
        logger.warning("job %s missing head_sha/base_ref, nothing to review", job.id)
        return True

    # The review handler's own wall clock, for the `reviews` row. Started
    # here rather than at the top of the function so the two early returns
    # above — neither of which reviews or posts anything — are excluded,
    # and deliberately not process_job's JOB_PROCESSING_SECONDS, which is
    # the caller's timer and also covers ack and the stats write itself.
    review_started = time.perf_counter()

    token = get_installation_token(installation_id)
    settings = get_settings()

    repo_config = load_repo_config(token, owner, repo, base_ref)

    # Started as early as possible — before the potentially 100+ second
    # ingestion+review-graph run below — purely so the PR shows
    # "CodeGuard Review — in progress" instead of nothing while a
    # webhook-triggered review is in flight. A missing checks:write
    # permission (or any other failure) degrades to "no check run for
    # this PR," never a failed review — the PR Review below is the
    # actual content and is always attempted regardless.
    try:
        check_run_id = start_check_run(token, owner, repo, head_sha)
    except requests.HTTPError:
        CHECK_RUNS_FAILED.labels(stage="start").inc()
        logger.warning("failed to start check run for pr=%s (missing checks:write permission?)", pr_number, exc_info=True)
        check_run_id = None

    diff_result = await ingest_pr_diff(token, owner, repo, pr_number, head_sha, repo_config, settings)
    _log_diff_ingestion_result(pr_number, repo_config, diff_result)

    # Semgrep/Bandit/Ruff on the same file content diff ingestion already
    # fetched (no second round of GitHub calls) and the same patches
    # (for exact changed-line filtering). base-tree eval-hygiene fetch
    # runs concurrently with the tool run — independent GitHub/subprocess
    # work, no reason to serialize them. Skipped (empty dict, no GitHub
    # calls at all) when the repo has opted out of the AI-aware agent.
    tool_findings_task = asyncio.ensure_future(run_tools_on_files(diff_result.file_contents, diff_result.patches))
    # OSV dependency-CVE lookup — deterministic, no LLM, and
    # not gated on enable_ai_aware (it has nothing to do with AI-aware
    # review; a known-vulnerable pin matters regardless). Doesn't fit
    # RUNNERS/run_tools_on_files: it needs the diff itself (patches) to
    # tell an added/bumped pin from one that was already there, not just
    # file content — see osv_runner.py's own docstring.
    osv_task = asyncio.ensure_future(
        asyncio.to_thread(check_dependency_updates, diff_result.dependency_contents, diff_result.dependency_patches)
    )
    if repo_config.enable_ai_aware:
        base_tree_task = asyncio.ensure_future(fetch_base_tree_python_files(token, owner, repo, base_ref))
    else:
        base_tree_task = None
    tool_findings = await tool_findings_task
    osv_findings = await osv_task
    base_tree_files = await base_tree_task if base_tree_task is not None else {}
    _log_findings(pr_number, tool_findings)
    if osv_findings:
        logger.info("pr=%s: %d known-vulnerability finding(s) from OSV", pr_number, len(osv_findings))

    # Prefetch every (path, content_hash, agent) this PR's
    # agents could possibly check — computed the same way the graph's
    # own route_to_* functions decide what to dispatch (compute_cache_keys),
    # so this is exactly what's needed, not a broader guess. A hit means
    # the corresponding node skips its LLM call entirely.
    cache_keys = compute_cache_keys(diff_result.file_contents, diff_result.patches, tool_findings, repo_config.enable_ai_aware)
    hunk_cache_hits = await fetch_cache_hits(pool, owner, repo, cache_keys)
    logger.info("hunk cache pr=%s: %d key(s) checked, %d hit", pr_number, len(cache_keys), len(hunk_cache_hits))

    # Fingerprints this repo has already marked false_positive
    # via a reply on a past PR — see codeguard/pipeline/feedback.py.
    suppressed_fingerprints = frozenset(await fetch_suppressed_fingerprints(pool, owner, repo))
    if suppressed_fingerprints:
        logger.info("pr=%s: %d suppressed fingerprint(s) for %s/%s", pr_number, len(suppressed_fingerprints), owner, repo)

    initial_state: ReviewState = {
        "owner": owner, "repo": repo, "pr_number": pr_number, "head_sha": head_sha,
        "installation_id": installation_id, "repo_config": repo_config,
        "files": diff_result.file_contents, "patches": diff_result.patches,
        "budget_exceeded": diff_result.budget_exceeded,
        "tool_findings": tool_findings, "base_tree_files": base_tree_files,
        "hunk_cache_hits": hunk_cache_hits, "cache_writes": [], "verdict_call_failures": [],
        "suppressed_fingerprints": suppressed_fingerprints,
        "touches_ai_code": False,
        "findings": [], "repo_level_findings": osv_findings, "dismissed_findings": [], "fix_suggestions": [],
        "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
    }
    final_state = await review_graph.ainvoke(initial_state)
    logger.info(
        "pipeline pr=%s: touches_ai_code=%s should_fix=%s inline=%d total_findings=%d fix_suggestions=%d "
        "tokens_in=%d tokens_out=%d estimated_cost_usd=%.4f cache_writes=%d",
        pr_number, final_state["touches_ai_code"], final_state["should_fix"],
        len(final_state["inline_findings"]), len(final_state["findings"]) + len(final_state["repo_level_findings"]),
        len(final_state["fix_suggestions"]),
        final_state["tokens_in"], final_state["tokens_out"], final_state["estimated_cost_usd"],
        len(final_state["cache_writes"]),
    )
    await write_cache_records(pool, final_state["cache_writes"])

    comments = _findings_to_review_comments(final_state["inline_findings"], final_state["fix_suggestions"])
    try:
        review_id = post_review(token, owner, repo, pr_number, head_sha, final_state["summary"], comments)
    except requests.HTTPError as exc:
        REVIEWS_FAILED.inc()
        retry_after = extract_retry_after(exc.response) if exc.response is not None else None
        if retry_after is not None:
            raise RateLimited(retry_after) from exc
        raise

    await _record_review_posted(pool, job)
    REVIEWS_POSTED.inc()

    # Best-effort — a failure here only costs future feedback on this
    # PR's comments (the reply -> fingerprint lookup will simply miss),
    # never the review itself, which already posted successfully.
    if comments:
        try:
            posted = fetch_review_comments(token, owner, repo, pr_number, review_id)
            comment_fingerprints = {}
            for c in posted:
                match = FINGERPRINT_MARKER_RE.search(c["body"])
                if match:
                    comment_fingerprints[c["id"]] = match.group(1)
            await record_posted_finding_comments(pool, owner, repo, pr_number, comment_fingerprints)
        except requests.HTTPError:
            logger.warning("failed to fetch/record posted finding comments for pr=%s", pr_number, exc_info=True)

    # Hoisted out of the check-run branch below: the `reviews` row must
    # record the same suppressed-excluded set the Check Run gates on, so
    # the two can never disagree about what this review found.
    all_findings = _exclude_suppressed(final_state["findings"] + final_state["repo_level_findings"], suppressed_fingerprints)

    conclusion = None
    if check_run_id is not None:
        conclusion, title, blocking = _check_run_conclusion(all_findings, repo_config.gate_threshold)
        summary = render_check_summary(
            findings=all_findings,
            tool_findings=tool_findings,
            blocking=blocking,
            gate_threshold=repo_config.gate_threshold,
            files_seen=diff_result.files_seen,
            files_reviewed=len(diff_result.files_reviewed),
            budget_exceeded=diff_result.budget_exceeded,
            fix_suggestion_count=len(final_state["fix_suggestions"]),
            dismissed_count=len(final_state["dismissed_findings"]),
            tokens_in=final_state["tokens_in"],
            tokens_out=final_state["tokens_out"],
            estimated_cost_usd=final_state["estimated_cost_usd"],
            duration_s=time.perf_counter() - review_started,
        )
        try:
            complete_check_run(token, owner, repo, check_run_id, conclusion=conclusion, title=title, summary=summary)
            CHECK_RUNS_COMPLETED.labels(conclusion=conclusion).inc()
        except requests.HTTPError:
            CHECK_RUNS_FAILED.labels(stage="complete").inc()
            logger.warning("failed to complete check run %s for pr=%s", check_run_id, pr_number, exc_info=True)

    # Last thing before returning: everything above is known by now,
    # including the Check Run conclusion, which is only decided after the
    # review has already been posted. record_review never raises (see its
    # module docstring) — the review is live on GitHub at this point, and a
    # stats failure must not skip the ack and cause a redelivery that posts
    # it a second time.
    await record_review(
        pool,
        job_id=job.id, owner=owner, repo=repo, pr_number=pr_number,
        head_sha=head_sha, action=payload.get("action", ""),
        summary_body=final_state["summary"],
        check_conclusion=conclusion,
        gate_threshold=repo_config.gate_threshold.name,
        fix_threshold=repo_config.fix_threshold.name,
        files_seen=diff_result.files_seen,
        files_reviewed=len(diff_result.files_reviewed),
        findings=all_findings,
        dismissed=final_state["dismissed_findings"],
        inline_count=len(final_state["inline_findings"]),
        fix_suggestions=final_state["fix_suggestions"],
        budget_exceeded=diff_result.budget_exceeded,
        filtered_files=diff_result.files_filtered,
        tokens_in=final_state["tokens_in"],
        tokens_out=final_state["tokens_out"],
        estimated_cost_usd=final_state["estimated_cost_usd"],
        duration_s=time.perf_counter() - review_started,
        node_latencies=final_state["node_latencies"],
        verdict_call_failures=final_state["verdict_call_failures"],
    )

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
