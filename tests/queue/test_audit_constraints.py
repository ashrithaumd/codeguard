"""Migration 010: the 'rejected' state and per-requester in-flight limit.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
Two separate problems.

1. One requester could queue unlimited concurrent audits. The only
   in-flight constraint was per REPOSITORY, so fifty audits of fifty
   different repos by one person were all allowed -- fifty clones and
   fifty lots of Anthropic spend, against a budget with no per-user cap
   by design.

2. request_audit() raised a single AuditInFlight carrying the existing
   row, and the route redirected to it. Once a visitor audit is visible
   only to its requester, redirecting requester B to requester A's audit
   hands B a URL for a row B must not see. The leak is created by our own
   in-flight rule, not by an attacker.
"""

from __future__ import annotations

import pytest

from codeguard.api.audits import (
    AuditInFlightMine,
    AuditInFlightOther,
    finish_audit,
    request_audit,
)

OWNER = "acme"


async def _request(pool, repo, who):
    return await request_audit(
        pool, owner=OWNER, repo=repo, requested_by=who, private=False,
    )


async def test_rejected_is_a_valid_status(pool):
    """Migration 010 widens the CHECK. Before it, this INSERT is refused."""
    audit = await _request(pool, "widgets", "alice")
    await finish_audit(pool, audit["id"], status="rejected",
                       error="This repository is too large to audit.")
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT status FROM audits WHERE id = %s", (audit["id"],))
        assert (await cur.fetchone())["status"] == "rejected"


async def test_rejected_frees_the_repo_and_the_user(pool):
    """A rejected audit is terminal, so neither partial index still covers
    it -- otherwise "too large" would block the repo forever."""
    audit = await _request(pool, "widgets", "alice")
    await finish_audit(pool, audit["id"], status="rejected", error="too large")

    again = await _request(pool, "widgets", "alice")
    assert again["id"] != audit["id"]


async def test_one_requester_cannot_queue_two_audits(pool):
    """The per-user limit. Different repos, same person -- the per-repo
    index does not catch this, which is why 010 adds a second one."""
    first = await _request(pool, "widgets", "alice")

    with pytest.raises(AuditInFlightMine) as caught:
        await _request(pool, "gadgets", "alice")

    # Their own audit, so handing back the id is correct: the route
    # redirects them to the thing they already started.
    assert caught.value.existing["id"] == first["id"]


async def test_a_different_requester_is_not_shown_the_other_audit(pool):
    """The leak our own in-flight rule would have created.

    B asks for a repo A is auditing. B must be refused WITHOUT being given
    A's audit id, because a visitor audit is visible only to its requester.
    """
    a = await _request(pool, "widgets", "alice")

    with pytest.raises(AuditInFlightOther) as caught:
        await _request(pool, "widgets", "bob")

    exc = caught.value
    assert "alice" not in str(exc), "must not name the other requester"
    assert str(a["id"]) not in str(exc), "must not leak the other audit's id"
    assert not hasattr(exc, "existing"), "must not carry the row at all"


async def test_two_requesters_may_audit_different_repos_at_once(pool):
    """Neither constraint should stop ordinary concurrent use."""
    await _request(pool, "widgets", "alice")
    bob = await _request(pool, "gadgets", "bob")
    assert bob["status"] == "queued"


async def test_the_per_user_index_releases_when_the_audit_finishes(pool):
    first = await _request(pool, "widgets", "alice")
    await finish_audit(pool, first["id"], status="done", report_markdown="#")

    second = await _request(pool, "gadgets", "alice")
    assert second["id"] != first["id"]
