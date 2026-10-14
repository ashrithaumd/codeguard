"""PR reviews: changed npm/yarn/pnpm, Go, Maven/Gradle and NuGet lockfiles.

Ingestion lists them (head path -> base path) without changing anything it
did before: a lockfile is still filtered from review with the same reason.
The worker fetches each at head and at base, raw (a package-lock.json is
often over the contents API's 1 MB), and hands both to OSV-Scanner, which
reports only what is new at head. A Python-only PR fetches and runs
nothing.
"""

from __future__ import annotations

from unittest.mock import patch

import requests

from codeguard.config import RepoConfig, Settings, get_settings
from codeguard.diff.ingest import ingest_pr_diff
from codeguard.tools.osv_runner import DependencyCheck
from codeguard.worker.main import MAX_LOCKFILES_PER_PR, prepare_lockfile_check


def _pr_file(name, status="modified", **extra):
    return {"filename": name, "status": status, "additions": 1, "deletions": 0, "patch": "@@ -1 +1 @@\n-a\n+b", **extra}


async def _ingest(raw_files, repo_config=None):
    with patch("codeguard.diff.ingest.get_pr_files", return_value=raw_files), \
         patch("codeguard.diff.ingest.get_file_content", return_value="x = 1\n"):
        return await ingest_pr_diff("tok", "o", "r", 1, "sha", repo_config or RepoConfig(), Settings(**get_settings().model_dump()))


async def test_ingestion_lists_changed_lockfiles_and_filters_them_as_before():
    raw = [_pr_file("app.py"), _pr_file("web/package-lock.json"), _pr_file("go.mod"),
           _pr_file("svc/pom.xml"), _pr_file("api/packages.lock.json"),
           _pr_file("new/yarn.lock", status="renamed", previous_filename="old/yarn.lock"),
           _pr_file("gone/pnpm-lock.yaml", status="removed"),
           _pr_file("node_modules/x/package-lock.json"), _pr_file("poetry.lock"), _pr_file("requirements.txt")]
    result = await _ingest(raw)
    assert result.lockfile_paths == {
        "web/package-lock.json": "web/package-lock.json", "go.mod": "go.mod", "svc/pom.xml": "svc/pom.xml",
        "api/packages.lock.json": "api/packages.lock.json", "new/yarn.lock": "old/yarn.lock"}
    # Unchanged: what the review says about these files.
    reasons = {f.path: f.reason for f in result.files_filtered}
    assert reasons["web/package-lock.json"] == "lockfile/generated/docs/vendored"
    assert "web/package-lock.json" not in result.file_contents


async def test_ignored_paths_are_honoured():
    result = await _ingest([_pr_file("examples/package-lock.json")], RepoConfig(ignored_paths=["examples/*"]))
    assert result.lockfile_paths == {}


async def test_a_python_only_pr_fetches_and_runs_nothing():
    with patch("codeguard.worker.main.get_file_raw") as fetch, \
         patch("codeguard.worker.main.scan_pr_lockfiles") as scan:
        assert await prepare_lockfile_check("tok", "o", "r", "head", "main", {}) == DependencyCheck([])
    fetch.assert_not_called()
    scan.assert_not_called()


def _fetcher(store, fail=()):
    def fetch(token, owner, repo, path, ref, max_bytes):
        if (path, ref) in fail:
            raise requests.HTTPError("boom")
        return store.get((path, ref))
    return fetch


async def test_head_and_base_are_fetched_and_compared():
    store = {("web/package-lock.json", "head"): "HEAD", ("web/package-lock.json", "main"): "BASE",
             ("new/yarn.lock", "head"): "Y"}  # renamed from old/yarn.lock, which the base does not have
    with patch("codeguard.worker.main.get_file_raw", side_effect=_fetcher(store)), \
         patch("codeguard.worker.main.scan_pr_lockfiles", return_value=DependencyCheck(["f"])) as scan:
        check = await prepare_lockfile_check("tok", "o", "r", "head", "main",
                                             {"web/package-lock.json": "web/package-lock.json",
                                              "new/yarn.lock": "old/yarn.lock"})
    assert check == DependencyCheck(["f"])
    head, base = scan.call_args.args
    assert head == {"web/package-lock.json": "HEAD", "new/yarn.lock": "Y"}
    assert base == {"web/package-lock.json": "BASE"}
    assert scan.call_args.kwargs["base_paths"] == {"web/package-lock.json": "web/package-lock.json",
                                                   "new/yarn.lock": "old/yarn.lock"}


async def test_a_fetch_that_fails_is_the_note_not_a_clean_result():
    store = {("go.mod", "head"): "module x\n", ("go.mod", "main"): "module x\n"}
    for fail in ({("go.mod", "head")}, {("go.mod", "main")}):
        with patch("codeguard.worker.main.get_file_raw", side_effect=_fetcher(store, fail)), \
             patch("codeguard.worker.main.scan_pr_lockfiles", return_value=DependencyCheck([])) as scan:
            check = await prepare_lockfile_check("tok", "o", "r", "head", "main", {"go.mod": "go.mod"})
        assert check.unavailable is True
        scan.assert_not_called()


async def test_beyond_the_cap_the_rest_are_not_checked_and_it_says_so():
    paths = {f"p{i}/go.mod": f"p{i}/go.mod" for i in range(MAX_LOCKFILES_PER_PR + 2)}
    store = {(p, ref): "module x\n" for p in paths for ref in ("head", "main")}
    with patch("codeguard.worker.main.get_file_raw", side_effect=_fetcher(store)), \
         patch("codeguard.worker.main.scan_pr_lockfiles", return_value=DependencyCheck([])) as scan:
        check = await prepare_lockfile_check("tok", "o", "r", "head", "main", paths)
    assert len(scan.call_args.args[0]) == MAX_LOCKFILES_PER_PR
    assert check.unavailable is True
