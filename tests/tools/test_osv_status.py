""""Dependency CVE check unavailable": Python's check is unchanged -- the
same pins, the same queries, the same findings -- and when OSV cannot be
reached it now SAYS so instead of looking like a clean result. Only the
note is new."""

from __future__ import annotations

from unittest.mock import Mock, patch

import requests

from codeguard.tools.osv_runner import (
    DEPENDENCY_CHECK_UNAVAILABLE,
    check_dependency_updates,
    check_dependency_updates_status,
)

FILES = {"requirements.txt": "pyyaml==5.3\n"}
PATCHES = {"requirements.txt": "@@ -1 +1 @@\n-x\n+pyyaml==5.3\n"}


def _osv_ok():
    batch = Mock(status_code=200)
    batch.json.return_value = {"results": [{"vulns": [{"id": "GHSA-6757-jp84-gxfx"}]}]}
    detail = Mock(status_code=200)
    detail.json.return_value = {"id": "GHSA-6757-jp84-gxfx", "summary": "unsafe loading",
                                "database_specific": {"severity": "CRITICAL"}}
    return batch, detail


def test_the_wording_is_exact():
    assert DEPENDENCY_CHECK_UNAVAILABLE == "Dependency CVE check unavailable"


def test_python_findings_are_exactly_what_they_were():
    batch, detail = _osv_ok()
    with patch("codeguard.tools.osv_runner.requests.post", return_value=batch), \
         patch("codeguard.tools.osv_runner.requests.get", return_value=detail):
        before = check_dependency_updates(FILES, PATCHES)
        status = check_dependency_updates_status(FILES, PATCHES)
    assert [f.model_dump() for f in status.findings] == [f.model_dump() for f in before]
    assert len(before) == 1 and status.unavailable is False


def test_osv_unreachable_is_said_and_the_findings_are_unchanged():
    with patch("codeguard.tools.osv_runner.requests.post", side_effect=requests.ConnectionError("down")):
        before = check_dependency_updates(FILES, PATCHES)
        status = check_dependency_updates_status(FILES, PATCHES)
    assert before == [] and status.findings == []
    assert status.unavailable is True


def test_nothing_to_check_is_not_unavailable():
    with patch("codeguard.tools.osv_runner.requests.post") as post:
        status = check_dependency_updates_status({"requirements.txt": ""}, {"requirements.txt": "@@ -1 +1 @@\n-a\n+b\n"})
    assert status.findings == [] and status.unavailable is False
    post.assert_not_called()


def test_a_missing_detail_is_degraded_not_unavailable():
    batch, _ = _osv_ok()
    with patch("codeguard.tools.osv_runner.requests.post", return_value=batch), \
         patch("codeguard.tools.osv_runner.requests.get", side_effect=requests.ConnectionError("down")):
        status = check_dependency_updates_status(FILES, PATCHES)
    assert len(status.findings) == 1 and status.unavailable is False


# --- where the note appears -------------------------------------------------

def test_the_pr_summary_says_so_in_its_caution_block():
    from codeguard.worker.main import _summary_warnings
    from codeguard.tools.osv_runner import DependencyCheck
    with patch("codeguard.worker.main.semgrep_version_warning", return_value=None):
        assert _summary_warnings(DependencyCheck([], unavailable=True)) == [DEPENDENCY_CHECK_UNAVAILABLE]
        assert _summary_warnings(DependencyCheck([], unavailable=False)) == []


def test_the_audit_lists_it_among_the_reasons_it_is_incomplete(tmp_path):
    from codeguard.cli import run_audit
    from codeguard.tools.osv_runner import DependencyCheck
    (tmp_path / "run.js").write_text("function run(x) {\n  return x;\n}\n")
    output = tmp_path / "report.md"
    for unavailable in (True, False):
        with patch("codeguard.cli.check_dependency_updates_status", return_value=DependencyCheck([], unavailable)):
            run_audit(str(tmp_path), str(output), post_issue_flag=False)
        assert (DEPENDENCY_CHECK_UNAVAILABLE in output.read_text(encoding="utf-8")) is unavailable
