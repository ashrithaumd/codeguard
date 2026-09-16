"""Regression coverage for codeguard.api.routes.webhooks._handle_feedback_comment
— called directly (same convention as test_comment_idempotency.py
calling handle_pull_request_review directly) rather than through a full
HTTP+signature round trip, against a real Postgres (tests/pipeline/conftest.py's
`pool` fixture).
"""

from __future__ import annotations

from types import SimpleNamespace

from codeguard.api.routes.webhooks import _handle_feedback_comment
from codeguard.pipeline.feedback import (
    fetch_suppressed_fingerprints,
    record_posted_finding_comments,
)


def _fake_request(pool):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=pool)))


def _review_comment_payload(*, action="created", body, in_reply_to_id=None, user_type="User", comment_id=1):
    comment = {"id": comment_id, "body": body, "user": {"login": "alice", "type": user_type}}
    if in_reply_to_id is not None:
        comment["in_reply_to_id"] = in_reply_to_id
    return {
        "action": action,
        "comment": comment,
        "pull_request": {"number": 7},
        "repository": {"owner": {"login": "o"}, "name": "r"},
    }


async def test_false_positive_reply_suppresses_the_linked_fingerprint(pool):
    await record_posted_finding_comments(pool, "o", "r", 7, {42: "fp-target"})
    payload = _review_comment_payload(body="false positive — this is sanitized upstream", in_reply_to_id=42)

    await _handle_feedback_comment(_fake_request(pool), payload, "pull_request_review_comment")

    assert await fetch_suppressed_fingerprints(pool, "o", "r") == {"fp-target"}


async def test_thumbs_up_reply_is_recorded_but_does_not_suppress(pool):
    await record_posted_finding_comments(pool, "o", "r", 7, {43: "fp-other"})
    payload = _review_comment_payload(body="\U0001F44D nice catch", in_reply_to_id=43, comment_id=2)

    await _handle_feedback_comment(_fake_request(pool), payload, "pull_request_review_comment")

    assert await fetch_suppressed_fingerprints(pool, "o", "r") == set()


async def test_reply_not_in_reply_to_anything_we_posted_is_a_no_op_suppression(pool):
    payload = _review_comment_payload(body="false positive", in_reply_to_id=999999, comment_id=3)

    await _handle_feedback_comment(_fake_request(pool), payload, "pull_request_review_comment")

    assert await fetch_suppressed_fingerprints(pool, "o", "r") == set()


async def test_issue_comment_cannot_suppress_since_it_has_no_target(pool):
    """issue_comment is never threaded to a specific inline comment —
    there's no fingerprint to suppress, by design (see
    _handle_feedback_comment's own docstring)."""
    payload = {
        "action": "created",
        "comment": {"id": 5, "body": "false positive on all of these", "user": {"login": "bob", "type": "User"}},
        "issue": {"number": 9},
        "repository": {"owner": {"login": "o"}, "name": "r"},
    }

    await _handle_feedback_comment(_fake_request(pool), payload, "issue_comment")

    assert await fetch_suppressed_fingerprints(pool, "o", "r") == set()


async def test_bot_authored_comments_are_ignored():
    pool = None  # never reached — the function returns before touching the pool
    payload = _review_comment_payload(body="false positive", in_reply_to_id=42, user_type="Bot")

    await _handle_feedback_comment(_fake_request(pool), payload, "pull_request_review_comment")


async def test_ordinary_conversation_is_ignored():
    pool = None
    payload = _review_comment_payload(body="thanks, will look into it", in_reply_to_id=42)

    await _handle_feedback_comment(_fake_request(pool), payload, "pull_request_review_comment")


async def test_edited_action_is_ignored():
    pool = None
    payload = _review_comment_payload(action="edited", body="false positive", in_reply_to_id=42)

    await _handle_feedback_comment(_fake_request(pool), payload, "pull_request_review_comment")
