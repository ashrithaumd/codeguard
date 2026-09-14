import logging

from fastapi import APIRouter, Request, Response
from prometheus_client import Counter, Histogram

from codeguard.api.signature import is_valid_signature
from codeguard.config import get_settings
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

            # Phase 2: enqueue and return immediately — no GitHub API call
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
                    "pr_number": pr_number,
                    "action": action,
                    "head_sha": payload["pull_request"]["head"]["sha"],
                    # Phase 3: .codeguard.yml is always read from this —
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

        logger.info("Ignoring unhandled event type: %s", event)
        return {"status": "ignored"}
