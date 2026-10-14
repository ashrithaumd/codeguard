"""Audits: secrets in every non-Python file, reported; placeholders counted.

The audit reads non-Python text files with the same hardening as every
other file it reads (no symlink, nothing outside the clone, size-capped,
binary skipped) and hands them to Gitleaks. Findings go into the report
like any other. Placeholder-shaped values are counted inside the existing
Skipped section ("2 placeholder-shaped values"). A Gitleaks failure is an
incompleteness reason, never a silent clean result.
"""

from __future__ import annotations

import random
import string

from codeguard.cli import _collect_secret_scan_files, build_report_data, render_report
from codeguard.config import RepoConfig


def _key(seed):
    rng = random.Random(seed)
    return "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))


def test_non_python_text_files_are_collected_and_python_binary_and_vendored_are_not(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "app.yml").write_text("a: 1\n")
    (tmp_path / "app.py").write_text("x = 1\n")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\x00\xff\xfe")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.yml").write_text("a: 1\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("[core]\n")
    (tmp_path / "big.yml").write_text("a" * (3 * 1024 * 1024))
    assert set(_collect_secret_scan_files(tmp_path, RepoConfig())) == {"config/app.yml"}


def _kwargs(**over):
    kw = dict(target="https://github.com/o/r", files_scanned=1, files_ai_aware=0, ai_reviewed_findings=[],
              passthrough_findings=[], dismissed=[], eval_hygiene_findings=[], osv_findings=[], skipped_files=[],
              verdict_call_failures=[], unavailable_tools=[], tokens_in=0, tokens_out=0, estimated_cost_usd=0.0,
              elapsed_s=1.0)
    kw.update(over)
    return kw


def test_placeholders_are_counted_in_the_report_and_its_skipped_section():
    data = build_report_data(**_kwargs(secret_placeholders=2))
    assert data["summary"]["secret_placeholders"] == 2
    text = render_report(**_kwargs(secret_placeholders=2))
    assert "2 placeholder-shaped value(s)" in text


def test_no_placeholders_changes_nothing():
    assert "placeholder-shaped" not in render_report(**_kwargs())


def test_a_secrets_scan_that_did_not_run_makes_the_audit_incomplete():
    data = build_report_data(**_kwargs(unavailable_tools=["gitleaks"]))
    assert any("gitleaks" in reason for reason in data["incomplete"])
