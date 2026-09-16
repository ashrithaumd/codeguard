"""Regression coverage for osv_runner.py's own logic — pin extraction
from a diff, severity mapping, and the batch-then-detail OSV flow — all
with requests mocked out, so this stays a network-free, deterministic
test file. tests/tools/test_runners_live.py carries the one real-network
check against the actual OSV API (same "live tests excluded from the
default run" convention as Bandit/Semgrep/Ruff there).
"""

from __future__ import annotations

from unittest.mock import Mock, patch

from codeguard.severity import Severity
from codeguard.tools.osv_runner import _iter_added_pins, _severity_from_osv, check_dependency_updates

REQUIREMENTS_PATCH = "@@ -1,2 +1,3 @@\n flask==2.0.0\n-pyyaml==5.2\n+pyyaml==5.3\n+requests==2.31.0\n"
PYPROJECT_PATCH = '@@ -1,3 +1,3 @@\n [project]\n dependencies = [\n-    "pyyaml>=5.0",\n+    "pyyaml==5.3",\n ]\n'


def _osv_vuln(vuln_id="GHSA-6757-jp84-gxfx", summary="unsafe loading", severity=None, fixed=None):
    vuln = {"id": vuln_id, "summary": summary, "affected": []}
    if severity:
        vuln["database_specific"] = {"severity": severity}
    if fixed:
        vuln["affected"] = [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": fixed}]}]}]
    return vuln


def test_iter_added_pins_only_yields_added_lines_from_requirements():
    pins = list(_iter_added_pins("requirements.txt", REQUIREMENTS_PATCH))
    assert ("pyyaml", "5.3") in pins
    assert ("requests", "2.31.0") in pins
    assert not any(name == "pyyaml" and version == "5.2" for name, version in pins)  # removed line, not added
    assert not any(name == "flask" for name, _ in pins)  # unchanged context line


def test_iter_added_pins_handles_pyproject_exact_pin():
    pins = list(_iter_added_pins("pyproject.toml", PYPROJECT_PATCH))
    assert pins == [("pyyaml", "5.3")]


def test_iter_added_pins_skips_pyproject_ranges():
    patch_text = '@@ -1 +1 @@\n-x\n+    "requests>=2.19.0,<3",\n'
    assert list(_iter_added_pins("pyproject.toml", patch_text)) == []


def test_severity_from_osv_prefers_database_specific_string():
    assert _severity_from_osv(_osv_vuln(severity="CRITICAL")) == Severity.CRITICAL
    assert _severity_from_osv(_osv_vuln(severity="MODERATE")) == Severity.MEDIUM


def test_severity_from_osv_falls_back_to_numeric_cvss():
    vuln = {"id": "x", "severity": [{"type": "CVSS_V3", "score": "9.8"}]}
    assert _severity_from_osv(vuln) == Severity.CRITICAL


def test_severity_from_osv_defaults_to_medium_when_unparseable():
    vuln = {"id": "x", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}]}
    assert _severity_from_osv(vuln) == Severity.MEDIUM


def test_check_dependency_updates_returns_empty_when_no_dependency_file_touched():
    findings = check_dependency_updates(files={}, patches={"app.py": "@@ -1 +1 @@\n-a\n+b\n"})
    assert findings == []


def test_check_dependency_updates_returns_empty_when_no_pins_added():
    patches = {"requirements.txt": "@@ -1 +1 @@\n context\n"}
    with patch("codeguard.tools.osv_runner.requests.post") as mock_post:
        findings = check_dependency_updates(files={"requirements.txt": ""}, patches=patches)
    mock_post.assert_not_called()
    assert findings == []


def test_check_dependency_updates_emits_a_finding_for_a_vulnerable_pin():
    files = {"requirements.txt": "flask==2.0.0\npyyaml==5.3\nrequests==2.31.0\n"}
    patches = {"requirements.txt": REQUIREMENTS_PATCH}

    batch_response = Mock(status_code=200)
    batch_response.json.return_value = {
        "results": [{"vulns": [{"id": "GHSA-6757-jp84-gxfx"}]}, {"vulns": []}],
    }
    detail_response = Mock(status_code=200)
    detail_response.json.return_value = _osv_vuln(severity="HIGH", fixed="5.4")

    with patch("codeguard.tools.osv_runner.requests.post", return_value=batch_response), \
         patch("codeguard.tools.osv_runner.requests.get", return_value=detail_response):
        findings = check_dependency_updates(files=files, patches=patches)

    assert len(findings) == 1
    f = findings[0]
    assert f.source_tool == "osv"
    assert f.rule_id == "GHSA-6757-jp84-gxfx"
    assert f.file == "requirements.txt"
    assert f.start_line == 2
    assert f.severity == Severity.HIGH
    assert "pyyaml==5.3" in f.message
    assert "Fixed in 5.4" in f.message


def test_check_dependency_updates_swallows_network_failure():
    import requests as requests_module

    patches = {"requirements.txt": REQUIREMENTS_PATCH}
    with patch("codeguard.tools.osv_runner.requests.post", side_effect=requests_module.ConnectionError("down")):
        findings = check_dependency_updates(files={"requirements.txt": ""}, patches=patches)

    assert findings == []


def test_check_dependency_updates_falls_back_to_bare_id_when_detail_fetch_fails():
    import requests as requests_module

    files = {"requirements.txt": "pyyaml==5.3\n"}
    patches = {"requirements.txt": "@@ -1 +1 @@\n-x\n+pyyaml==5.3\n"}

    batch_response = Mock(status_code=200)
    batch_response.json.return_value = {"results": [{"vulns": [{"id": "GHSA-6757-jp84-gxfx"}]}]}

    with patch("codeguard.tools.osv_runner.requests.post", return_value=batch_response), \
         patch("codeguard.tools.osv_runner.requests.get", side_effect=requests_module.ConnectionError("down")):
        findings = check_dependency_updates(files=files, patches=patches)

    assert len(findings) == 1
    assert findings[0].rule_id == "GHSA-6757-jp84-gxfx"
    assert "unknown" not in findings[0].message
