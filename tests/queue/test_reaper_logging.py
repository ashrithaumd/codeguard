"""The reaper's per-tick log LEVEL.

Separate from test_reaper.py because none of this needs Postgres:
reap_expired_leases is stubbed out, and what is under test is
run_forever's choice of level, not the sweep itself.

The behaviour matters operationally rather than functionally. At the 1s
interval the old unconditional INFO produced ~86,000 lines a day against
an idle production queue — measured, not estimated: 3,577/hour in Log
Analytics on 2026-09-23, every one of them "swept 0 row(s)". The risk in
fixing that is over-correcting into silence, so these tests pin both
directions: quiet ticks drop to DEBUG, and the two cases worth waking up
for stay at INFO.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from codeguard.queue import reaper
from codeguard.queue.models import DeadLetter, ReapResult


def _dead_letter() -> DeadLetter:
    import uuid
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    return DeadLetter(
        id=uuid.uuid4(),
        type="pull_request_review",
        payload={},
        idempotency_key="k",
        attempts=5,
        failed_reason="boom",
        moved_at=now,
        created_at=now,
    )


async def _run_ticks(monkeypatch, results, *, interval=0.0, delay=0.0):
    """Drive run_forever through exactly len(results) ticks, then stop it.

    Stopping via CancelledError from inside the stub rather than from
    outside: run_forever re-raises CancelledError untouched, so this ends
    the loop at a deterministic tick count instead of whenever a
    task.cancel() happened to land.
    """
    calls = {"n": 0}

    async def fake_reap(pool, *, max_attempts):
        if calls["n"] >= len(results):
            raise asyncio.CancelledError
        result = results[calls["n"]]
        calls["n"] += 1
        if delay:
            await asyncio.sleep(delay)
        return result

    monkeypatch.setattr(reaper, "reap_expired_leases", fake_reap)
    with pytest.raises(asyncio.CancelledError):
        await reaper.run_forever(object(), interval_seconds=interval, max_attempts=5)


def _tick_records(caplog):
    return [r for r in caplog.records if r.message.startswith("reaper tick")]


def test_a_zero_interval_does_not_make_every_tick_look_stalled():
    """Regression: the threshold was a bare multiple of the interval, so
    interval=0 put it at 0, every tick counted as "slower than zero", and
    the demotion silently reverted to INFO-per-tick — in the tightest-loop
    configuration, the one that can least afford it."""
    assert reaper._stall_threshold(0.0) == reaper._MIN_STALL_SECONDS
    assert reaper._stall_threshold(1.0) == 5.0
    assert reaper._stall_threshold(0.05) == reaper._MIN_STALL_SECONDS


async def test_a_quiet_sweep_logs_at_debug(monkeypatch, caplog):
    caplog.set_level(logging.DEBUG, logger="codeguard.queue.reaper")

    await _run_ticks(monkeypatch, [ReapResult(), ReapResult(), ReapResult()])

    records = _tick_records(caplog)
    assert len(records) == 3
    assert {r.levelno for r in records} == {logging.DEBUG}
    # Still carries the diagnostics — demoted, not stripped.
    assert "since previous tick" in records[0].message
    assert "[SLOW]" not in records[0].message


async def test_a_quiet_sweep_is_invisible_at_the_level_production_runs_at(monkeypatch, caplog):
    """api/main.py and worker/main.py both basicConfig at INFO. This is
    the assertion that actually cashes out the 86k lines."""
    caplog.set_level(logging.INFO, logger="codeguard.queue.reaper")

    await _run_ticks(monkeypatch, [ReapResult() for _ in range(5)])

    assert _tick_records(caplog) == []


async def test_a_requeue_logs_at_info(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="codeguard.queue.reaper")

    await _run_ticks(monkeypatch, [ReapResult(), ReapResult(requeued_count=2), ReapResult()])

    records = _tick_records(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.INFO
    assert "swept 2 row(s)" in records[0].message
    assert "2 requeued" in records[0].message


async def test_a_dead_letter_logs_at_info(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger="codeguard.queue.reaper")

    await _run_ticks(monkeypatch, [ReapResult(dead_lettered=[_dead_letter()])])

    records = _tick_records(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.INFO
    assert "1 dead-lettered" in records[0].message


async def test_a_stalled_tick_logs_at_info_even_with_nothing_to_sweep(monkeypatch, caplog):
    """The docstring's whole reason for recording took/since_prev is
    telling a stalled loop from a stalled query. Demoting quiet ticks
    must not take that with it: a sweep slower than _STALL_FACTOR x the
    interval is reported however empty it was."""
    caplog.set_level(logging.INFO, logger="codeguard.queue.reaper")
    # The real floor is 1.0s; lowered here so the test costs 0.08s rather
    # than over a second to prove the same branch.
    monkeypatch.setattr(reaper, "_MIN_STALL_SECONDS", 0.05)

    # threshold = max(5 x 0.01, 0.05) = 0.05 -> a 0.08s sweep is slow.
    await _run_ticks(monkeypatch, [ReapResult(), ReapResult()], interval=0.01, delay=0.08)

    records = _tick_records(caplog)
    assert records, "a stalled sweep must survive at INFO"
    assert all(r.levelno == logging.INFO for r in records)
    assert "[SLOW]" in records[-1].message


async def test_the_first_tick_is_never_called_slow(monkeypatch, caplog):
    """tick 1's since_prev is measured from loop entry rather than from a
    previous tick, so it must not be compared against the interval."""
    caplog.set_level(logging.INFO, logger="codeguard.queue.reaper")

    await _run_ticks(monkeypatch, [ReapResult()], interval=0.01)

    assert _tick_records(caplog) == []


async def test_a_failing_sweep_still_logs_an_exception(monkeypatch, caplog):
    """Unchanged by this: a raising sweep is ERROR with a traceback, and
    the loop keeps going."""
    caplog.set_level(logging.INFO, logger="codeguard.queue.reaper")
    calls = {"n": 0}

    async def fake_reap(pool, *, max_attempts):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("db went away")
        raise asyncio.CancelledError

    monkeypatch.setattr(reaper, "reap_expired_leases", fake_reap)
    with pytest.raises(asyncio.CancelledError):
        await reaper.run_forever(object(), interval_seconds=0.0, max_attempts=5)

    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1
    assert errors[0].exc_info is not None
    assert "db went away" in caplog.text
