import logging

from fastapi import APIRouter, Request, Response
from prometheus_client import Counter, Histogram

from codeguard.api.signature import is_valid_signature
from codeguard.config import get_settings
from codeguard.github.auth import get_installation_token
from codeguard.github.comments import post_comment

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

            # Temporary: posting synchronously in the request handler.
            # Moves behind the queue in Phase 2 — a slow/failed GitHub
            # API call shouldn't hold up webhook ack, and this is
            # exactly the ack-latency cost that motivates the queue.
            if action in ("opened", "synchronize"):
                try:
                    installation_id = payload["installation"]["id"]
                    owner = payload["repository"]["owner"]["login"]
                    repo = payload["repository"]["name"]
                    token = get_installation_token(installation_id)
                    post_comment(
                        token, owner, repo, pr_number,
                        "CodeGuard v2 connected — review pipeline coming soon.",
                    )
                    logger.info("Posted comment on pr=%s", pr_number)
                except Exception:
                    # Best-effort: a failure here shouldn't turn into a
                    # non-2xx response — GitHub already got a valid,
                    # verified delivery; retrying it wouldn't help.
                    logger.exception("Failed to post comment on pr=%s", pr_number)

            return {"status": "ok"}

        logger.info("Ignoring unhandled event type: %s", event)
        return {"status": "ignored"}
