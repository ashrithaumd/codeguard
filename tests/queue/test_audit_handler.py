"""The worker's repo_audit handler.

run_audit itself is not exercised here — tests/cli covers it, and running
a real audit would clone a repository and spend real money. What is
under test is the wrapper: that it records a terminal state either way,
that a failure says why, and above all that it does not block the event
loop.

That last one is the reason this handler exists rather than a direct
call. An audit takes minutes; the lease is 30s with a 10s heartbeat. A
synchronous run_audit on the event loop would starve heartbeat_loop, the
reaper would declare the job abandoned, and it would be redelivered
WHILE STILL RUNNING — a second clone and a second bill for one request.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from codeguard.api.audits import get_audit, request_audit
from codeguard.queue.models import Job
from codeguard.worker.main import handle_repo_audit

_NOW = datetime.now(timezone.utc)

OWNER = "acme"
REPO = "widgets"


def _job(audit_id) -> Job:
    return Job.from_record({
        "id": uuid.uuid4(), "type": "repo_audit",
        "payload": {"audit_id": str(audit_id), "owner": OWNER, "repo": REPO,
                    "target": f"https://github.com/{OWNER}/{REPO}"},
        "idempotency_key": f"repo_audit:{audit_id}", "status": "leased",
        "attempts": 1, "leased_by": "test", "leased_until": None,
        "run_after": _NOW, "created_at": _NOW, "updated_at": _NOW,
    })


async def _queued(pool):
    return await request_audit(
        pool, owner=OWNER, repo=REPO, requested_by="tester", private=False,
    )


async def test_a_successful_audit_is_recorded_done(pool, monkeypatch, tmp_path):
    audit = await _queued(pool)

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("# Audit report\n\nNothing found.\n")
        return 0, None

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    assert await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event()) is True

    row = await get_audit(pool, audit["id"])
    assert row["status"] == "done"
    assert row["exit_code"] == 0
    assert "Nothing found" in row["report_markdown"]
    assert row["error"] is None
    assert row["finished_at"] is not None
    assert row["duration_s"] > 0


async def test_a_failed_audit_records_the_reason(pool, monkeypatch):
    """"A failed audit must say why." run_audit returns its reason rather
    than raising, and that reason is what the page renders."""
    audit = await _queued(pool)
    monkeypatch.setattr(
        "codeguard.worker.main.run_audit",
        lambda target, output_path, post_issue, stats=None, deadline_s=None: (1, "git clone failed: not found"),
    )

    assert await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event()) is True

    row = await get_audit(pool, audit["id"])
    assert row["status"] == "failed"
    assert row["exit_code"] == 1
    assert "git clone failed" in row["error"]


async def test_an_unexpected_exception_still_reaches_a_terminal_state(pool, monkeypatch):
    """Nothing may leave an audit stuck on 'running'. A row that never
    reaches a terminal state also never releases the in-flight index
    entry, so the repo could never be audited again."""
    audit = await _queued(pool)

    def boom(target, output_path, post_issue, stats=None, deadline_s=None):
        raise RuntimeError("disk full")

    monkeypatch.setattr("codeguard.worker.main.run_audit", boom)
    assert await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event()) is True

    row = await get_audit(pool, audit["id"])
    assert row["status"] == "failed"
    assert "disk full" in row["error"]


async def test_a_finished_audit_frees_the_repo_for_another(pool, monkeypatch):
    audit = await _queued(pool)
    monkeypatch.setattr(
        "codeguard.worker.main.run_audit",
        lambda target, output_path, post_issue, stats=None, deadline_s=None: (0, None),
    )
    await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())

    # No AuditInFlight: the partial index only covers queued/running.
    second = await _queued(pool)
    assert second["id"] != audit["id"]


async def test_the_audit_does_not_block_the_event_loop(pool, monkeypatch):
    """The heartbeat test, stated as the thing it protects.

    run_audit is replaced with a synchronous sleep, and a concurrent
    ticker counts how many times it got to run. If the handler called
    run_audit directly the loop would be frozen and the ticker would be
    stuck at zero; through asyncio.to_thread it keeps running, which is
    exactly what lets heartbeat_loop renew the lease on a real audit.
    """
    import time as _time

    audit = await _queued(pool)
    monkeypatch.setattr(
        "codeguard.worker.main.run_audit",
        lambda target, output_path, post_issue, stats=None, deadline_s=None: (_time.sleep(0.4), (0, None))[1],
    )

    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await asyncio.sleep(0.02)
            ticks += 1

    beat = asyncio.create_task(ticker())
    try:
        await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())
    finally:
        beat.cancel()

    # ~20 ticks are possible in 0.4s; anything clearly above zero proves
    # the loop stayed free. Asserted loosely because CI timing varies.
    assert ticks >= 5, f"event loop was blocked during the audit (ticks={ticks})"


async def test_the_economics_are_recorded_not_just_printed(pool, monkeypatch):
    """Regression: the audits row recorded 0 tokens and $0 for every run
    while the report stored beside it said $0.0406.

    run_audit computes the cost, prints it and embeds it in the report,
    but returns only (exit_code, error) -- so finish_audit was called
    with its defaults. migration 009 declares these columns "same meaning
    as reviews', so the two can be summed without reconciling units",
    which made the under-report silent and wrong in the one place it
    would be believed.

    Invisible on the first live audit because that target had one trivial
    file: 0 findings meant no model call, so $0 was genuinely correct.
    Only a target with real findings exposed it.
    """
    audit = await _queued(pool)

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        if stats is not None:
            stats.tokens_in = 5853
            stats.tokens_out = 1533
            stats.estimated_cost_usd = 0.0406
            stats.duration_s = 35.9
        return 0, None

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())

    row = await get_audit(pool, audit["id"])
    assert row["tokens_in"] == 5853
    assert row["tokens_out"] == 1533
    assert row["estimated_cost_usd"] == 0.0406


async def test_a_failed_audit_still_records_what_it_spent(pool, monkeypatch):
    """A clone that succeeded and a verdict layer that then failed has
    still spent money. Recording zero there would hide real spend behind
    a failure."""
    audit = await _queued(pool)

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        if stats is not None:
            stats.tokens_in = 100
            stats.estimated_cost_usd = 0.002
        return 1, "something broke after the model calls"

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())

    row = await get_audit(pool, audit["id"])
    assert row["status"] == "failed"
    assert row["estimated_cost_usd"] == 0.002
    assert row["tokens_in"] == 100


async def test_a_lost_lease_writes_no_terminal_status(pool, monkeypatch):
    """The double-spend guard.

    handle_repo_audit never consulted `abandoned`, so a worker whose lease
    was reassigned mid-audit still wrote a terminal row -- racing the
    replica that had legitimately taken the job over. On a redelivery the
    loser's write could land on an audit the winner had already finished.

    This is the audit's equivalent of _review_already_posted: at-least-once
    delivery means the side effect needs its own guard, and here the side
    effect is the terminal row plus the Anthropic spend behind it.
    """
    audit = await _queued(pool)
    abandoned = asyncio.Event()

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        abandoned.set()          # the reaper reclaimed it while we worked
        return 0, None

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    completed = await handle_repo_audit(_job(audit["id"]), pool, abandoned)

    assert completed is False, "an abandoned job must not report completion"
    row = await get_audit(pool, audit["id"])
    assert row["status"] == "running", "the terminal write belongs to the lease owner"
    assert row["finished_at"] is None


# --------------------------------------------------------------------------
# Typed outcomes -> audits.status, mapped WITHOUT reading any message.
#
# Before this, run_audit returned (1, message) for a timeout, for a repo
# with no Python, and for every other refusal, and the worker turned exit
# code 1 into status 'failed'. "This repository is too large" and "the
# worker crashed" were stored identically, and the only thing telling them
# apart was the wording of a string.
# --------------------------------------------------------------------------

import pytest  # noqa: E402

from codeguard.cli import AuditOutcome  # noqa: E402


@pytest.mark.parametrize("outcome,expected_status", [
    (AuditOutcome.COMPLETED, "done"),
    (AuditOutcome.REJECTED, "rejected"),
    (AuditOutcome.TIMED_OUT, "timed_out"),
    (AuditOutcome.FAILED, "failed"),
])
async def test_each_outcome_maps_to_its_own_status(
    pool, monkeypatch, outcome, expected_status,
):
    audit = await _queued(pool)

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        if stats is not None:
            stats.outcome = outcome
            stats.message = None if outcome is AuditOutcome.COMPLETED else "because reasons"
        return (0 if outcome is AuditOutcome.COMPLETED else 1), None

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())

    row = await get_audit(pool, audit["id"])
    assert row["status"] == expected_status


async def test_the_status_does_not_follow_the_message_wording(pool, monkeypatch):
    """The whole point. A message that SAYS "too large" while the outcome
    says FAILED must store 'failed' -- so rewording copy can never change
    how an audit is recorded."""
    audit = await _queued(pool)

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        if stats is not None:
            stats.outcome = AuditOutcome.FAILED
            stats.message = "This repository is too large to audit."
        return 1, None

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())

    row = await get_audit(pool, audit["id"])
    assert row["status"] == "failed", "status follows the outcome, not the text"


async def test_a_rejection_message_reaches_the_row(pool, monkeypatch):
    """The user has to be told WHY, so stats.message is stored when
    run_audit did not return an error string of its own."""
    audit = await _queued(pool)

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        if stats is not None:
            stats.outcome = AuditOutcome.REJECTED
            stats.message = "CodeGuard currently analyzes Python repositories."
        return 1, None

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())

    row = await get_audit(pool, audit["id"])
    assert row["status"] == "rejected"
    assert "Python" in row["error"]


async def test_a_terminal_outcome_frees_the_repo_and_the_requester(pool, monkeypatch):
    """Every one of the four is terminal, so neither partial unique index
    still covers it. A 'timed_out' audit must not wedge the repository the
    way a stuck 'running' one did."""
    from codeguard.api.audits import request_audit

    audit = await _queued(pool)

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        if stats is not None:
            stats.outcome = AuditOutcome.TIMED_OUT
            stats.message = "took too long"
        return 1, None

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())

    again = await request_audit(
        pool, owner=OWNER, repo=REPO, requested_by="tester", private=False,
    )
    assert again["id"] != audit["id"]


async def test_the_structured_report_is_stored_beside_the_markdown(pool, monkeypatch):
    """The audit page renders audits.report_json. run_audit hands it over
    on AuditStats, the same out-parameter the economics travel on."""
    audit = await _queued(pool)
    data = {"version": 1, "summary": {"total": 1}, "findings": [{"file": "a.py", "start_line": 3}]}

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("# report\n")
        if stats is not None:
            stats.report = data
        return 0, None

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())

    row = await get_audit(pool, audit["id"])
    assert row["report_json"] == data
    assert row["report_markdown"] == "# report\n"


async def test_an_audit_without_structured_data_stores_null(pool, monkeypatch):
    audit = await _queued(pool)
    monkeypatch.setattr(
        "codeguard.worker.main.run_audit",
        lambda target, output_path, post_issue, stats=None, deadline_s=None: (1, "clone failed"),
    )
    await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())

    row = await get_audit(pool, audit["id"])
    assert row["report_json"] is None


async def test_the_audited_commit_is_stored(pool, monkeypatch):
    audit = await _queued(pool)
    sha = "4e02d10" + "b" * 33

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        if stats is not None:
            stats.commit_sha = sha
        return 0, None

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    await handle_repo_audit(_job(audit["id"]), pool, asyncio.Event())
    assert (await get_audit(pool, audit["id"]))["commit_sha"] == sha
