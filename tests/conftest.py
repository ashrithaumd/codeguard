"""Test-only: Semgrep runs with one job and a per-file memory cap, so the
suite fits on a memory-tight machine (a full run was killed for low memory
on 2026-10-10). Production flags are untouched -- only the two command
builders are wrapped, and the flags go before the scan target, which stays
last."""

from __future__ import annotations

import pytest

SEMGREP_TEST_FLAGS = ["--jobs", "1", "--max-memory", "1024"]


@pytest.fixture(autouse=True)
def _semgrep_low_memory(monkeypatch):
    from codeguard.tools import semgrep_runner

    for name in ("_build_cmd", "_build_vendor_cmd"):
        original = getattr(semgrep_runner, name)

        def wrapped(tmp_dir, _original=original):
            cmd = _original(tmp_dir)
            return cmd[:-1] + SEMGREP_TEST_FLAGS + cmd[-1:]

        monkeypatch.setattr(semgrep_runner, name, wrapped)
