"""Bridges a dead-lettered queue job back to a GitHub comment. Deliberately
its own module rather than living in codeguard/queue/ — the queue package
stays domain-agnostic (it returns structured DeadLetter data and has no
idea what a "PR" or an "installation" is); this is the wiring that gives
that data GitHub-specific meaning. Used from two call sites: the worker's
job handler (nack() exhausting attempts) and the API's reaper callback
(a crash-looping job dead-lettered without ever calling nack()) — both
dead-lettering paths need the same notice.
"""

from __future__ import annotations

import logging

from codeguard.github.auth import get_installation_token
from codeguard.github.comments import post_comment
from codeguard.queue.models import DeadLetter

logger = logging.getLogger("codeguard.github.notifications")

DEAD_LETTER_COMMENT = (
    "CodeGuard couldn't review this PR — push a new commit to retry."
)


async def notify_dead_letter(dead_letter: DeadLetter) -> None:
    """Best-effort: failure to post this comment is only logged, never
    raised — a dead-lettered job is already the failure case; a second
    failure notifying about it shouldn't cause any further disruption
    (e.g. crashing the reaper loop or the worker's own error handling).
    """
    payload = dead_letter.payload
    try:
        owner = payload["owner"]
        repo = payload["repo"]
        pr_number = payload["pr_number"]
        installation_id = payload["installation_id"]
    except KeyError:
        logger.exception("dead letter %s missing expected payload fields, cannot notify", dead_letter.id)
        return

    try:
        token = get_installation_token(installation_id)
        post_comment(token, owner, repo, pr_number, DEAD_LETTER_COMMENT)
        logger.info("posted dead-letter notice on pr=%s (job %s)", pr_number, dead_letter.id)
    except Exception:
        logger.exception("failed to post dead-letter notice for job %s (pr=%s) — logged only", dead_letter.id, pr_number)
