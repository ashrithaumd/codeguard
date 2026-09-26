"""handle_repo_audit must leave no temporary directory behind.

The worker half of the cleanup checks; tests/cli/test_audit_cleanup.py
covers run_audit's own clone directory. Split by fixture rather than by
topic: `pool` is defined in tests/queue/conftest.py.

THE VULNERABILITY THIS REPRODUCES
handle_repo_audit creates an output directory per audit and removes it in
a `finally`. Nothing asserted that, on any path. A leak fills the worker's
disk with attacker-supplied repository content, on the filesystem of the
process holding the Anthropic key and the GitHub App key.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import pytest

_REAL_MKDTEMP = tempfile.mkdtemp


@pytest.fixture
def created_dirs(monkeypatch):
    made: list[str] = []

    def spy(*args, **kwargs):
        path = _REAL_MKDTEMP(*args, **kwargs)
        made.append(path)
        return path

    monkeypatch.setattr(tempfile, "mkdtemp", spy)
    return made


def _assert_all_gone(made: list[str], expect_at_least: int = 1):
    assert len(made) >= expect_at_least, (
        f"expected at least {expect_at_least} temp dir(s), got {made}"
    )
    survivors = [p for p in made if os.path.exists(p)]
    assert not survivors, f"temporary directories left behind: {survivors}"


async def _audit_row(pool):
    from codeguard.api.audits import request_audit
    return await request_audit(
        pool, owner="acme", repo="widgets", requested_by="tester", private=False,
    )


def _job_for(audit_id):
    import uuid
    from datetime import datetime, timezone

    from codeguard.queue.models import Job

    now = datetime.now(timezone.utc)
    return Job.from_record({
        "id": uuid.uuid4(), "type": "repo_audit",
        "payload": {"audit_id": str(audit_id), "owner": "acme", "repo": "widgets",
                    "target": "https://github.com/acme/widgets"},
        "idempotency_key": f"repo_audit:{audit_id}", "status": "leased",
        "attempts": 1, "leased_by": "t", "leased_until": now,
        "run_after": now, "created_at": now, "updated_at": now,
    })


async def test_the_worker_cleans_up_on_success(pool, created_dirs, monkeypatch):
    from codeguard.worker.main import handle_repo_audit

    audit = await _audit_row(pool)

    def fake_run_audit(target, output_path, post_issue, stats=None, deadline_s=None):
        Path(output_path).write_text("# report\n", encoding="utf-8")
        return 0, None

    monkeypatch.setattr("codeguard.worker.main.run_audit", fake_run_audit)
    await handle_repo_audit(_job_for(audit["id"]), pool, asyncio.Event())

    _assert_all_gone(created_dirs)


async def test_the_worker_cleans_up_when_the_handler_raises(pool, created_dirs, monkeypatch):
    from codeguard.worker.main import handle_repo_audit

    audit = await _audit_row(pool)

    def boom(target, output_path, post_issue, stats=None, deadline_s=None):
        raise RuntimeError("disk full")

    monkeypatch.setattr("codeguard.worker.main.run_audit", boom)
    await handle_repo_audit(_job_for(audit["id"]), pool, asyncio.Event())

    _assert_all_gone(created_dirs)


async def test_the_worker_cleans_up_when_cancelled(pool, created_dirs, monkeypatch):
    """SIGTERM path. process_job cancels the handler task, and `finally`
    runs on CancelledError — so the worker's own directory goes.

    Documents a known limit rather than hiding it: cancelling
    asyncio.to_thread does NOT stop the thread, so run_audit's own clone
    directory is cleaned by its own `finally` whenever that thread
    eventually finishes. Late, not never.
    """
    from codeguard.worker.main import handle_repo_audit

    audit = await _audit_row(pool)
    started = asyncio.Event()

    def slow(target, output_path, post_issue, stats=None, deadline_s=None):
        import time as _t
        started.set()
        _t.sleep(0.5)
        return 0, None

    monkeypatch.setattr("codeguard.worker.main.run_audit", slow)

    task = asyncio.create_task(
        handle_repo_audit(_job_for(audit["id"]), pool, asyncio.Event())
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The worker's output dir is gone immediately.
    _assert_all_gone(created_dirs)
    # And the loop's executor is drained so the abandoned thread cannot
    # trip a later test's teardown.
    await asyncio.get_running_loop().shutdown_default_executor()
