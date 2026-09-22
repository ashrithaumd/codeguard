import logging

from fastapi import APIRouter, Request, Response
from prometheus_client import Counter, Histogram

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
feedback_suppressions_total = Counter(
    "codeguard_feedback_suppressions_total",
    "Fingerprints newly suppressed via a false_positive reply.",
)


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
            # duplicate job.
            if action in ("opened", "synchronize"):
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

        if event == "pull_request_review_comment":
            await _handle_feedback_comment(request, payload, event)
            return {"status": "ok"}

        if event == "issue_comment":
            await _handle_feedback_comment(request, payload, event)
            return {"status": "ok"}

        logger.info("Ignoring unhandled event type: %s", event)
        return {"status": "ignored"}


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
