"""Regression coverage for codeguard.pipeline.feedback — signal
parsing (pure) and the DB round-trips (against a real Postgres, same
convention as test_hunk_cache.py) for the feedback loop.
"""

from __future__ import annotations

from codeguard.pipeline.feedback import (
    fetch_fingerprint_for_comment,
    fetch_suppressed_fingerprints,
    fingerprint_marker,
    parse_feedback_signal,
    record_feedback,
    record_posted_finding_comments,
    suppress_fingerprint,
)


def test_parse_feedback_signal_false_positive_wins_over_thumbs_up():
    assert parse_feedback_signal("false positive :+1: agreed, not a real issue \U0001F44D") == "false_positive"


def test_parse_feedback_signal_thumbs_down():
    assert parse_feedback_signal("\U0001F44E disagree with this one") == "negative"


def test_parse_feedback_signal_thumbs_up():
    assert parse_feedback_signal("\U0001F44D nice catch") == "positive"


def test_parse_feedback_signal_ordinary_conversation_is_none():
    assert parse_feedback_signal("thanks, will fix in a follow-up PR") is None


def test_parse_feedback_signal_hyphenated_false_positive():
    assert parse_feedback_signal("this is a false-positive, the value is always sanitized upstream") == "false_positive"


def test_fingerprint_marker_round_trips_via_regex():
    from codeguard.pipeline.feedback import FINGERPRINT_MARKER_RE

    body = f"some comment text\n\n{fingerprint_marker('abc123def4567890')}"
    match = FINGERPRINT_MARKER_RE.search(body)

    assert match is not None
    assert match.group(1) == "abc123def4567890"


async def test_posted_comment_round_trips_to_fingerprint(pool):
    await record_posted_finding_comments(pool, "o", "r", 1, {111: "fp-aaa"})

    assert await fetch_fingerprint_for_comment(pool, "o", "r", 111) == "fp-aaa"
    assert await fetch_fingerprint_for_comment(pool, "o", "r", 999) is None


async def test_fetch_suppressed_fingerprints_empty_by_default(pool):
    assert await fetch_suppressed_fingerprints(pool, "o", "r") == set()


async def test_suppress_fingerprint_then_fetch(pool):
    await suppress_fingerprint(pool, owner="o", repo="r", fingerprint="fp-bbb", reason="false positive", suppressed_by="alice")

    assert await fetch_suppressed_fingerprints(pool, "o", "r") == {"fp-bbb"}


async def test_suppress_fingerprint_scoped_to_repo(pool):
    await suppress_fingerprint(pool, owner="o", repo="repo-a", fingerprint="fp-ccc", reason="fp", suppressed_by="alice")

    assert await fetch_suppressed_fingerprints(pool, "o", "repo-a") == {"fp-ccc"}
    assert await fetch_suppressed_fingerprints(pool, "o", "repo-b") == set()


async def test_suppress_fingerprint_on_conflict_does_nothing(pool):
    await suppress_fingerprint(pool, owner="o", repo="r", fingerprint="fp-ddd", reason="first", suppressed_by="alice")
    await suppress_fingerprint(pool, owner="o", repo="r", fingerprint="fp-ddd", reason="second", suppressed_by="bob")

    assert await fetch_suppressed_fingerprints(pool, "o", "r") == {"fp-ddd"}


async def test_record_feedback_with_and_without_a_fingerprint(pool):
    await record_feedback(
        pool, owner="o", repo="r", fingerprint="fp-eee", pr_number=1, comment_id=1,
        commenter="alice", signal="positive", body=":+1:", source_event="pull_request_review_comment",
    )
    await record_feedback(
        pool, owner="o", repo="r", fingerprint=None, pr_number=1, comment_id=2,
        commenter="bob", signal="negative", body=":-1: overall", source_event="issue_comment",
    )
    # No assertion on a SELECT here — record_feedback has no matching
    # fetch helper (feedback is written for audit/metrics, not read back
    # by the pipeline); this just proves neither call raises, including
    # the NULL-fingerprint (issue_comment) path.
