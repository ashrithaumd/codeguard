"""The worker's side of impact analysis: prepare_impact.

Off unless Settings.impact_analysis_enabled AND the repo's
enable_impact_analysis are both on; then one tarball request for the head,
base versions of the changed .py files only, and analyze(). A repository
too large, or a fetch that fails, is a note in the review ("Impact analysis
skipped: ..."), never a failed review. GitHub is mocked throughout.
"""

from __future__ import annotations

import difflib
from unittest.mock import patch

from codeguard.config import RepoConfig, Settings, get_settings
from codeguard.github.tarball import TarballTooLarge
from codeguard.worker.main import impact_enabled, prepare_impact

BASE = "def charge(amount, currency):\n    return amount\n"
HEAD = "def charge(amount, currency, *, key):\n    return amount\n"
CALLER = "from billing.charge import charge\ncharge(1, 'usd')\n"


def _patch(base, head, path):
    return "".join(difflib.unified_diff(base.splitlines(True), head.splitlines(True), f"a/{path}", f"b/{path}"))


def _settings(**over) -> Settings:
    base = get_settings().model_dump()
    base.update(over)
    return Settings(**base)


def test_it_is_off_by_default():
    assert Settings.model_fields["impact_analysis_enabled"].default is False
    assert not impact_enabled(_settings(impact_analysis_enabled=False), RepoConfig())


def test_it_needs_both_switches():
    assert impact_enabled(_settings(impact_analysis_enabled=True), RepoConfig())
    assert not impact_enabled(_settings(impact_analysis_enabled=True), RepoConfig(enable_impact_analysis=False))


async def test_one_tarball_and_base_files_for_changed_python_only():
    patches = {"billing/charge.py": _patch(BASE, HEAD, "billing/charge.py"), "README.md": "@@ -1 +1 @@\n-a\n+b\n",
               "billing/new.py": "@@ -0,0 +1 @@\n+x = 1\n"}
    base_calls = []

    def fake_base(token, owner, repo, path, ref):
        base_calls.append((path, ref))
        return BASE if path == "billing/charge.py" else None

    with patch("codeguard.worker.main.fetch_python_files",
               return_value={"billing/charge.py": HEAD, "api/checkout.py": CALLER}) as tarball, \
         patch("codeguard.worker.main.get_file_content", side_effect=fake_base):
        report, notes = await prepare_impact("tok", "acme", "shop", "h" * 40, "main",
                                             {"billing/charge.py": HEAD}, patches, _settings())
    tarball.assert_called_once()
    assert tarball.call_args.args[:4] == ("tok", "acme", "shop", "h" * 40)
    assert sorted(base_calls) == [("billing/charge.py", "main"), ("billing/new.py", "main")]
    assert notes == []
    assert [(s.path, s.mismatch) for s in report.sites] == [
        ("api/checkout.py", "missing required keyword argument 'key'")]


async def test_a_repository_too_large_is_skipped_with_a_note():
    with patch("codeguard.worker.main.fetch_python_files", side_effect=TarballTooLarge("big")), \
         patch("codeguard.worker.main.get_file_content", return_value=BASE):
        report, notes = await prepare_impact("tok", "a", "b", "h" * 40, "main", {}, {"x.py": "@@"}, _settings())
    assert report is None and notes == ["skipped: repository too large"]


async def test_a_failed_fetch_is_skipped_with_a_note_not_raised():
    with patch("codeguard.worker.main.fetch_python_files", side_effect=RuntimeError("502")), \
         patch("codeguard.worker.main.get_file_content", return_value=BASE):
        report, notes = await prepare_impact("tok", "a", "b", "h" * 40, "main", {}, {"x.py": "@@"}, _settings())
    assert report is None and notes == ["skipped: could not fetch the repository"]


async def test_no_python_changes_means_no_fetch_at_all():
    with patch("codeguard.worker.main.fetch_python_files") as tarball, \
         patch("codeguard.worker.main.get_file_content") as base:
        report, notes = await prepare_impact("tok", "a", "b", "h" * 40, "main", {}, {"README.md": "@@"}, _settings())
    tarball.assert_not_called()
    base.assert_not_called()
    assert report is None and notes == []


async def test_a_bug_in_the_analysis_is_a_note_not_a_failed_review():
    patches = {"billing/charge.py": _patch(BASE, HEAD, "billing/charge.py")}
    with patch("codeguard.worker.main.fetch_python_files", return_value={}), \
         patch("codeguard.worker.main.get_file_content", return_value=BASE), \
         patch("codeguard.worker.main.analyze", side_effect=ValueError("bug")):
        report, notes = await prepare_impact("tok", "a", "b", "h" * 40, "main", {}, patches, _settings())
    assert report is None and notes == ["skipped: analysis failed"]
