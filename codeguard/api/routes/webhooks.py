import logging

from fastapi import APIRouter, Request, Response
from prometheus_client import Counter, Histogram

from codeguard.api import access, repo_notices, repo_settings
from codeguard.api.signature import is_valid_signature
from codeguard.config import get_settings
from codeguard.pipeline.feedback import (
    fetch_fingerprint_for_comment,
    parse_feedback_signal,
    record_feedback,
    suppress_fingerprint,
)
from codeguard.queue.queue import enqueue

logger = logging.getLogger(__name__)
router = APIRouter()

webhooks_received_total = Counter(
    "codeguard_webhooks_received_total",
    "Webhook deliveries received, before signature verification.",
)
webhooks_verified_total = Counter(
    "codeguard_webhooks_verified_total",
    "Webhook deliveries that passed signature verification.",
)
webhooks_rejected_total = Counter(
    "codeguard_webhooks_rejected_total",
    "Webhook deliveries rejected for a bad or missing signature.",
)
webhook_ack_latency_seconds = Histogram(
    "codeguard_webhook_ack_latency_seconds",
    "Time from receiving a webhook delivery to acknowledging it.",
)
feedback_signals_total = Counter(
    "codeguard_feedback_signals_total",
    "Recognized feedback comments, by signal and which webhook event carried them.",
    ["signal", "source_event"],
)
pr_reviews_skipped_total = Counter(
    "codeguard_pr_reviews_skipped_total",
    "pull_request deliveries acknowledged without queueing a review, by reason.",
    ["reason"],
)
feedback_suppressions_total = Counter(
    "codeguard_feedback_suppressions_total",
    "Fingerprints newly suppressed via a false_positive reply.",
)


SKIP_LABEL = "codeguard:skip"

# The actions that can start a review. unlabeled only when the label
# removed is SKIP_LABEL; checked below.
_REVIEW_ACTIONS = ("opened", "synchronize", "ready_for_review", "unlabeled")


def _has_skip_label(pull_request: dict) -> bool:
    return any(
        str(label.get("name", "")).strip().lower() == SKIP_LABEL
        for label in pull_request.get("labels") or []
    )


async def _head_already_reviewed(pool, owner: str, repo: str, pr_number: int, head_sha: str) -> bool:
    """A review row for this exact head, or a review job for it that is
    still pending or running.

    NOT a finished job: the worker marks a job done when it skips it (the
    switch turned off while it was queued) without writing a review, and
    that head was never reviewed.
    """
    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            SELECT EXISTS (
                SELECT 1 FROM reviews
                WHERE lower(owner) = lower(%(owner)s) AND lower(repo) = lower(%(repo)s)
                  AND pr_number = %(pr)s AND head_sha = %(head)s
            ) OR EXISTS (
                SELECT 1 FROM jobs
                WHERE type = 'pull_request_review' AND status IN ('pending', 'leased')
                  AND lower(payload->>'owner') = lower(%(owner)s)
                  AND lower(payload->>'repo') = lower(%(repo)s)
                  AND (payload->>'pr_number')::int = %(pr)s
                  AND payload->>'head_sha' = %(head)s
            ) AS seen
            """,
            {"owner": owner, "repo": repo, "pr": pr_number, "head": head_sha},
        )
        return bool((await cur.fetchone())["seen"])


async def should_review(pool, payload: dict) -> str:
    """Whether a pull_request delivery becomes a review.

    Returns "review", "ignore", or the reason it is skipped. In order, the
    first that applies decides:

      repo switch OFF            pr_reviews_off  (migrations/014)
      codeguard:skip label       skip_label
      draft                      draft      -- reviewed once marked ready
      head already reviewed or   already_reviewed
        queued for review
      opened / synchronize /     review
        ready_for_review /
        unlabeled codeguard:skip
      anything else              ignore

    Removing the skip label or marking a draft ready reviews the head as it
    stands, once: toggling either back and forth does not pay for the same
    head twice.
    """
    action = payload.get("action")
    if action == "unlabeled":
        removed = str((payload.get("label") or {}).get("name", "")).strip().lower()
        if removed != SKIP_LABEL:
            return "ignore"
    elif action not in _REVIEW_ACTIONS and action != "labeled":
        return "ignore"

    owner = payload["repository"]["owner"]["login"]
    repo = payload["repository"]["name"]
    pull_request = payload.get("pull_request") or {}

    if not await repo_settings.pr_reviews_enabled(pool, owner, repo):
        return "pr_reviews_off"
    if _has_skip_label(pull_request):
        return "skip_label"
    if action == "labeled":
        # Any other label: labelling a PR is not a reason to review it.
        return "ignore"
    if pull_request.get("draft"):
        return "draft"
    if await _head_already_reviewed(pool, owner, repo, payload.get("number"), pull_request["head"]["sha"]):
        return "already_reviewed"
    return "review"


@router.post("/webhook")
async def webhook(request: Request, response: Response):
    with webhook_ack_latency_seconds.time():
        webhooks_received_total.inc()

        # Read raw bytes BEFORE anything parses this as JSON — verification
        # must run against exactly what GitHub sent. Starlette caches the
        # body, so a later `.json()` call on this same request reuses these
        # bytes rather than re-reading the stream.
        raw_body = await request.body()
        signature_header = request.headers.get("X-Hub-Signature-256")

        settings = get_settings()
        if not is_valid_signature(settings.github_webhook_secret, raw_body, signature_header):
            webhooks_rejected_total.inc()
            logger.warning("Webhook rejected: invalid or missing signature")
            response.status_code = 401
            return {"error": "invalid signature"}

        webhooks_verified_total.inc()

        event = request.headers.get("X-GitHub-Event", "unknown")
        payload = await request.json()

        if event == "ping":
            logger.info("Webhook ping received (zen: %s)", payload.get("zen"))
            return {"status": "pong"}

        if event == "pull_request":
            action = payload.get("action")
            pr_number = payload.get("number")
            logger.info("pull_request event: action=%s pr=%s", action, pr_number)

            # Enqueue and return immediately — no GitHub API call
            # happens on this request path at all. delivery_id (GitHub's
            # own X-GitHub-Delivery) is the idempotency key, so a webhook
            # redelivery of the same delivery is a no-op enqueue, not a
            # duplicate job. Whether this delivery is a review at all is
            # should_review's decision; see its docstring for the order.
            decision = await should_review(request.app.state.pool, payload)
            if decision == "ignore":
                return {"status": "ignored"}
            if decision != "review":
                pr_reviews_skipped_total.labels(reason=decision).inc()
                logger.info("pull_request %s/%s#%s (%s) skipped: %s",
                            payload["repository"]["owner"]["login"], payload["repository"]["name"],
                            pr_number, action, decision)
                return {"status": "skipped", "reason": decision}

            delivery_id = request.headers.get("X-GitHub-Delivery")
            job_payload = {
                "installation_id": payload["installation"]["id"],
                "owner": payload["repository"]["owner"]["login"],
                "repo": payload["repository"]["name"],
                # Captured here, at the only point GitHub tells us,
                # so the review row can record it (migrations/007).
                # Defaults to True when absent: an unknown visibility
                # is treated as private, since the dashboard renders
                # findings, file paths and source fragments.
                "private": bool(payload["repository"].get("private", True)),
                # Recorded per review so the dashboard can be searched
                # by title (migrations/008) — nobody remembers a pull
                # request by its number. Attacker-controlled text, and
                # length-capped here so a pathological title cannot
                # bloat every job payload and review row that follows.
                "pr_title": str(payload["pull_request"].get("title") or "")[:300],
                "pr_number": pr_number,
                "action": action,
                "head_sha": payload["pull_request"]["head"]["sha"],
                # .codeguard.yml is always read from this —
                # the base branch, never the head — see
                # codeguard/github/repo_config.py.
                "base_ref": payload["pull_request"]["base"]["ref"],
            }
            job, created = await enqueue(
                request.app.state.pool,
                type="pull_request_review",
                payload=job_payload,
                idempotency_key=delivery_id,
            )
            logger.info("%s job %s for pr=%s (delivery=%s)",
                        "enqueued" if created else "already enqueued", job.id, pr_number, delivery_id)
            return {"status": "ok"}

        if event in ("installation", "installation_repositories"):
            await _handle_installation_change(request.app.state.pool, event, payload)
            return {"status": "ok"}

        if event == "pull_request_review_comment":
            await _handle_feedback_comment(request, payload, event)
            return {"status": "ok"}

        if event == "issue_comment":
            await _handle_feedback_comment(request, payload, event)
            return {"status": "ok"}

        logger.info("Ignoring unhandled event type: %s", event)
        return {"status": "ignored"}


def _repo_entries(entries) -> list[tuple[str, str, bool]]:
    """(owner, repo, private) from GitHub's installation repository list,
    which carries full_name rather than an owner object. Unknown visibility
    is private, as everywhere else."""
    out = []
    for entry in entries or []:
        owner, _, name = str(entry.get("full_name", "")).partition("/")
        if owner and name:
            out.append((owner, name, bool(entry.get("private", True))))
    return out


async def _handle_installation_change(pool, event: str, payload: dict) -> None:
    """Repositories joining or leaving the App's installation.

      installation_repositories added    -> a "New repository" notice each
      installation_repositories removed  -> their notices are dropped
      installation created               -> notices for the initial list
      installation deleted               -> their notices are dropped

    With the App on "All repositories", GitHub sends `added` when a
    repository is created, forked into the account or transferred in; that
    is the whole of "a new repository" as far as anything here can know.
    These events reach every App without subscribing to them.

    Not best-effort, unlike the feedback handler: if the notice cannot be
    written, a 5xx lets GitHub's delivery log show the failure.
    """
    action = payload.get("action")
    if event == "installation_repositories":
        added = _repo_entries(payload.get("repositories_added"))
        removed = _repo_entries(payload.get("repositories_removed"))
    elif action == "created":
        added, removed = _repo_entries(payload.get("repositories")), []
    elif action == "deleted":
        added, removed = [], _repo_entries(payload.get("repositories"))
    else:
        return

    access.installation_changed([(o, r) for o, r, _ in added + removed])
    await repo_notices.announce(pool, added)
    await repo_notices.forget(pool, [(o, r) for o, r, _ in removed])
    logger.info("%s %s: %d repo(s) added, %d removed", event, action, len(added), len(removed))


async def _handle_feedback_comment(request: Request, payload: dict, event: str) -> None:
    """Feedback loop. Handles both events that can carry a
    reply to one of CodeGuard's own comments:

    - pull_request_review_comment (action="created"): a threaded reply
      under one of our INLINE finding comments. `comment.in_reply_to_id`
      is the parent comment's id — if that parent is one we posted (see
      posted_finding_comments, populated right after post_review()),
      the reply is tied to a specific fingerprint and a "false_positive"
      signal actually suppresses it for this repo.
    - issue_comment (action="created"): general PR-conversation comment,
      never threaded to a specific inline comment — GitHub gives no way
      to associate it with one finding. Recorded (fingerprint=None) for
      visibility/metrics only; never triggers suppression.

    Deliberately best-effort and NEVER raises back to the webhook
    handler: a DB hiccup here should never turn into a 500 on a webhook
    delivery GitHub would otherwise just retry pointlessly (this isn't
    the core review flow, unlike the pull_request branch above).

    NOTE on 👍/👎: GitHub has no webhook event for someone adding an
    emoji REACTION to a comment (checked against GitHub's own webhook
    event catalog, not assumed) — only these two comment-created events
    exist. What this actually recognizes is a THUMBS EMOJI TYPED INTO A
    REPLY's text (or the phrase "false positive"), not the reaction
    picker. Capturing true reactions would need polling each posted
    comment's reactions endpoint, which isn't implemented here.
    """
    comment = payload.get("comment")
    if payload.get("action") != "created" or comment is None:
        return
    if comment.get("user", {}).get("type") == "Bot":
        return  # never treat our own (or any bot's) comment as feedback

    body = comment.get("body", "")
    signal = parse_feedback_signal(body)
    if signal is None:
        return

    owner = payload["repository"]["owner"]["login"]
    repo = payload["repository"]["name"]
    commenter = comment.get("user", {}).get("login", "unknown")
    comment_id = comment["id"]
    pr_number = payload.get("pull_request", {}).get("number") or payload.get("issue", {}).get("number")
    pool = request.app.state.pool

    fingerprint = None
    if event == "pull_request_review_comment":
        in_reply_to = comment.get("in_reply_to_id")
        if in_reply_to is not None:
            fingerprint = await fetch_fingerprint_for_comment(pool, owner, repo, in_reply_to)

    try:
        await record_feedback(
            pool, owner=owner, repo=repo, fingerprint=fingerprint, pr_number=pr_number,
            comment_id=comment_id, commenter=commenter, signal=signal, body=body, source_event=event,
        )
        feedback_signals_total.labels(signal=signal, source_event=event).inc()

        if signal == "false_positive" and fingerprint is not None:
            await suppress_fingerprint(
                pool, owner=owner, repo=repo, fingerprint=fingerprint,
                reason=f"reply from {commenter} on PR #{pr_number}: {body[:200]}", suppressed_by=commenter,
            )
            feedback_suppressions_total.inc()
            logger.info("suppressed fingerprint %s for %s/%s (reported by %s)", fingerprint, owner, repo, commenter)
    except Exception:
        logger.warning("failed to record feedback for %s/%s comment=%s", owner, repo, comment_id, exc_info=True)
