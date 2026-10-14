"""OSV-Scanner over npm/yarn/pnpm, Go, Maven/Gradle and NuGet lockfiles.

Python's dependency check (tools/osv_runner.py) is untouched: Python's
manifests and lockfiles are never handed to OSV-Scanner. A PR reports only
vulnerabilities new at head (base vs head); an audit reports everything.
OSV unreachable, the binary missing or output that cannot be read is the
"Dependency CVE check unavailable" note, never a clean result.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from codeguard.severity import Severity
from codeguard.tools.osv_runner import DependencyCheck
from codeguard.tools.osv_scanner_runner import (
    EXPECTED_VERSION,
    MAX_LOCKFILE_BYTES,
    combine,
    is_osv_lockfile,
    scan_lockfiles,
    scan_pr_lockfiles,
)

LOCK = (
    '{\n  "name": "x",\n  "lockfileVersion": 3,\n  "packages": {\n'
    '    "node_modules/lodash": {\n      "version": "4.17.15"\n    }\n  }\n}\n'
)
LOCK_FIXED = LOCK.replace("4.17.15", "4.17.21")

LODASH_VULN = {
    "id": "GHSA-29mw-wpgm-hmr9",
    "summary": "Regular Expression Denial of Service (ReDoS) in lodash",
    "aliases": ["CVE-2020-28500"],
    "database_specific": {"severity": "MODERATE"},
    "affected": [
        {"package": {"ecosystem": "npm", "name": "lodash-es"}, "ranges": [{"events": [{"introduced": "4.0.0"}, {"fixed": "9.9.9"}]}]},
        {"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]}]},
    ],
}
LODASH_CRITICAL = {"id": "GHSA-p6mc-m468-83gw", "summary": "Prototype Pollution in lodash",
                   "aliases": ["CVE-2020-8203"], "database_specific": {"severity": "HIGH"}, "affected": []}


def _result(path, name, version, vulns, ecosystem="npm"):
    return {"source": {"path": path, "type": "lockfile"},
            "packages": [{"package": {"name": name, "version": version, "ecosystem": ecosystem},
                          "vulnerabilities": vulns,
                          "groups": [{"ids": [v["id"]], "aliases": [v["id"], *v.get("aliases", [])]} for v in vulns]}]}


def _fake_run(results_for, returncode=1, stdout=None):
    """subprocess.run stand-in: reads the -L paths the runner wrote and
    answers with whatever results_for(side, basename, content) returns."""
    calls = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        paths = [cmd[i + 1].split(":", 1)[1] for i, a in enumerate(cmd) if a == "-L"]
        results = []
        for p in paths:
            content = Path(p).read_text(encoding="utf-8")
            side = "base" if "/base/" in p.replace("\\", "/") else "head"
            results.extend(results_for(side, Path(p).name, content, p))
        out = stdout if stdout is not None else json.dumps({"results": results})
        return subprocess.CompletedProcess(cmd, returncode, out, "")
    return run, calls


def _lodash(side, name, content, path):
    if "4.17.15" in content:
        return [_result(path, "lodash", "4.17.15", [LODASH_VULN])]
    return []


def test_the_new_ecosystems_are_lockfiles_and_python_is_never_one():
    for name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "pom.xml",
                 "gradle.lockfile", "buildscript-gradle.lockfile", "packages.lock.json"):
        assert is_osv_lockfile(f"svc/{name}"), name
    for name in ("requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock", "uv.lock",
                 "Gemfile.lock", "Cargo.lock", "composer.lock", "package.json", "go.sum",
                 "node_modules/x/package-lock.json", "vendor/x/go.mod"):
        assert not is_osv_lockfile(name), name


def test_the_command_is_pinned_down():
    run, calls = _fake_run(_lodash)
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=run):
        scan_lockfiles({"web/package-lock.json": LOCK})
    cmd, kwargs = calls[0]
    assert cmd[1:3] == ["scan", "source"]
    for flag in ("--no-resolve", "--no-call-analysis=all", "--format", "json"):
        assert flag in cmd
    # Each lockfile explicitly, parsed as its own kind: nothing else in a
    # repository is ever scanned, and a path can never be read as a kind.
    assert [cmd[i + 1].split(":", 1)[0] for i, a in enumerate(cmd) if a == "-L"] == ["package-lock.json"]
    # No credential reaches it: its environment is a short allowlist.
    assert "ANTHROPIC_API_KEY" not in kwargs["env"] and "GITHUB_APP_PRIVATE_KEY" not in kwargs["env"]


def test_an_audit_reports_every_vulnerability_with_the_lockfile_line():
    run, _ = _fake_run(_lodash)
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=run):
        check = scan_lockfiles({"web/package-lock.json": LOCK})
    assert check.unavailable is False
    [f] = check.findings
    assert (f.file, f.start_line, f.source_tool, f.rule_id) == ("web/package-lock.json", 6, "osv", "GHSA-29mw-wpgm-hmr9")
    assert f.severity == Severity.MEDIUM
    # The fixed version is lodash's own, not lodash-es's listed first.
    assert f.message == ("lodash@4.17.15 has a known vulnerability (GHSA-29mw-wpgm-hmr9): "
                         "Regular Expression Denial of Service (ReDoS) in lodash. Fixed in 4.17.21.")


def test_the_fixed_version_is_the_one_for_the_installed_line():
    """minimist 1.2.0: the record's first fix is for the 0.x line (0.2.1);
    the one that applies is 1.2.3. When no range holds the version, say
    nothing rather than name the wrong fix."""
    from codeguard.tools.osv_scanner_runner import _fixed_for

    vuln = {"affected": [{"package": {"ecosystem": "npm", "name": "minimist"}, "ranges": [
        {"events": [{"introduced": "0"}, {"fixed": "0.2.1"}]},
        {"events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]}]}]}
    assert _fixed_for(vuln, "minimist", "1.2.0", "npm") == "1.2.3"
    assert _fixed_for(vuln, "minimist", "0.1.0", "npm") == "0.2.1"
    assert _fixed_for(vuln, "minimist", "2.0.0", "npm") is None
    go = {"affected": [{"package": {"ecosystem": "Go", "name": "github.com/gin-gonic/gin"}, "ranges": [
        {"events": [{"introduced": "0"}, {"fixed": "1.7.7"}, {"introduced": "1.8.0"}, {"fixed": "1.9.0"}]}]}]}
    assert _fixed_for(go, "github.com/gin-gonic/gin", "1.6.0", "Go") == "1.7.7"
    assert _fixed_for(go, "github.com/gin-gonic/gin", "v1.8.1", "Go") == "1.9.0"


def test_nothing_to_scan_runs_nothing():
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run") as run:
        assert scan_lockfiles({}) == DependencyCheck([])
        assert scan_pr_lockfiles({}, {}) == DependencyCheck([])
    run.assert_not_called()


def test_clean_is_clean():
    run, _ = _fake_run(lambda *a: [], returncode=0)
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=run):
        assert scan_lockfiles({"go.mod": "module x\n"}) == DependencyCheck([])


def test_osv_unreachable_is_the_note_not_a_clean_result():
    # What 2.6.0 really does with no network: exit 127, empty results.
    run, _ = _fake_run(lambda *a: [], returncode=127)
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=run):
        assert scan_lockfiles({"web/package-lock.json": LOCK}) == DependencyCheck([], unavailable=True)


def test_a_missing_binary_a_timeout_or_garbage_is_the_note():
    for effect in (FileNotFoundError("osv-scanner"), subprocess.TimeoutExpired("osv-scanner", 1)):
        with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=effect):
            assert scan_lockfiles({"web/package-lock.json": LOCK}).unavailable is True
    run, _ = _fake_run(lambda *a: [], stdout="not json")
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=run):
        assert scan_lockfiles({"web/package-lock.json": LOCK}).unavailable is True


def test_a_pr_reports_only_what_is_new_at_head():
    def answer(side, name, content, path):
        vulns = [LODASH_VULN] + ([LODASH_CRITICAL] if side == "head" else [])
        return [_result(path, "lodash", "4.17.15", vulns)]
    run, _ = _fake_run(answer)
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=run):
        check = scan_pr_lockfiles({"package-lock.json": LOCK}, {"package-lock.json": LOCK})
    assert [f.rule_id for f in check.findings] == ["GHSA-p6mc-m468-83gw"]
    assert check.findings[0].severity == Severity.HIGH


def test_the_same_vulnerability_under_an_alias_is_not_new():
    renamed = {**LODASH_VULN, "id": "CVE-2020-28500", "aliases": ["GHSA-29mw-wpgm-hmr9"]}

    def answer(side, name, content, path):
        return [_result(path, "lodash", "4.17.15", [LODASH_VULN if side == "head" else renamed])]
    run, _ = _fake_run(answer)
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=run):
        assert scan_pr_lockfiles({"package-lock.json": LOCK}, {"package-lock.json": LOCK}).findings == []


def test_a_fix_or_a_new_lockfile():
    run, _ = _fake_run(_lodash)
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=run):
        # The PR fixes it: nothing new.
        assert scan_pr_lockfiles({"package-lock.json": LOCK_FIXED}, {"package-lock.json": LOCK}).findings == []
        # A lockfile the base did not have: everything in it is new.
        assert len(scan_pr_lockfiles({"package-lock.json": LOCK}, {}).findings) == 1


def test_a_renamed_lockfile_compares_against_its_old_path():
    run, _ = _fake_run(_lodash)
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=run):
        check = scan_pr_lockfiles({"web/package-lock.json": LOCK}, {"app/package-lock.json": LOCK},
                                  base_paths={"web/package-lock.json": "app/package-lock.json"})
    assert check.findings == []


def test_paths_never_reach_the_command_line_or_the_filesystem_as_given():
    run, calls = _fake_run(_lodash)
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run", side_effect=run):
        check = scan_lockfiles({"a:b/../../package-lock.json": LOCK})
    assert "a:b" not in " ".join(calls[0][0])
    assert [f.file for f in check.findings] == ["a:b/../../package-lock.json"]


def test_an_oversized_lockfile_is_not_scanned_and_says_so():
    big = "x" * (MAX_LOCKFILE_BYTES + 1)
    with patch("codeguard.tools.osv_scanner_runner.subprocess.run") as run:
        assert scan_lockfiles({"package-lock.json": big}) == DependencyCheck([], unavailable=True)
    run.assert_not_called()


def test_combine_keeps_python_findings_first_and_either_failure_is_the_note():
    py = DependencyCheck(["py"], unavailable=False)
    assert combine(py, DependencyCheck([])) == py
    assert combine(py, DependencyCheck(["lock"])) == DependencyCheck(["py", "lock"])
    assert combine(DependencyCheck([], True), DependencyCheck(["lock"])) == DependencyCheck(["lock"], True)
    assert combine(py, DependencyCheck([], True)).unavailable is True


def test_the_pinned_version():
    assert EXPECTED_VERSION == "2.6.0"


def test_the_summary_and_fixed_in_are_separated_once():
    # "...choosing boundary Fixed in 4.0.4." on openai-quickstart-node: OSV
    # summaries rarely end in a period. One is added, never doubled.
    from codeguard.tools.osv_scanner_runner import _Vuln, _finding

    def message(summary):
        record = {"id": "GHSA-x", "summary": summary,
                  "affected": [{"package": {"name": "form-data", "ecosystem": "npm"},
                                "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.0.4"}]}]}]}
        v = _Vuln(("k", "npm", "form-data"), frozenset({"GHSA-x"}), "form-data", "4.0.1", "npm", record)
        return _finding("package-lock.json", '"form-data": "4.0.1"', v).message

    assert message("unsafe random function for choosing boundary").endswith("choosing boundary. Fixed in 4.0.4.")
    assert message("Already a sentence.").endswith("Already a sentence. Fixed in 4.0.4.")
