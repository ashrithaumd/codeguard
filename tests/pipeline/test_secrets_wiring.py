"""Where Gitleaks findings go, and where they never go.

PR reviews: ingestion builds sparse added-lines files for every changed
non-Python file from the patches GitHub already sent (no extra fetch); the
worker scans them and puts the findings straight into the review's results.
They are never routed to a verdict agent and never to the fix agent: nothing
about a secret reaches a model. Python files are untouched.

Audits: findings are reported like any other; placeholder-shaped values are
counted inside the existing Skipped section; a Gitleaks failure is said.
"""

from __future__ import annotations

import random
import string
from unittest.mock import patch

from codeguard.config import RepoConfig, get_settings
from codeguard.diff.ingest import ingest_pr_diff
from codeguard.pipeline.nodes import route_after_fanin
from codeguard.severity import Severity
from codeguard.tools.gitleaks_runner import SecretScan
from codeguard.tools.models import Finding
from codeguard.worker.main import prepare_secrets


def _key(seed):
    rng = random.Random(seed)
    return "ghp_" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(36))


def _pr_file(name, patch_text, additions=1):
    return {"filename": name, "additions": additions, "deletions": 0, "patch": patch_text}


async def _ingest(raw_files):
    with patch("codeguard.diff.ingest.get_pr_files", return_value=raw_files), \
         patch("codeguard.diff.ingest.get_file_content", return_value="x = 1\n") as fetch:
        result = await ingest_pr_diff("tok", "o", "r", 1, "sha", RepoConfig(), get_settings())
    return result, fetch


async def test_ingestion_builds_sparse_files_for_changed_non_python_files_without_fetching_them():
    raw = [_pr_file("app.py", "@@ -0,0 +1 @@\n+x = 1"),
           _pr_file("config/app.yml", "@@ -1,2 +1,3 @@\n a: 1\n+token: t\n b: 2"),
           _pr_file("gone.yml", "@@ -1 +0,0 @@\n-a: 1", additions=0)]
    result, fetch = await _ingest(raw)
    assert result.secret_scan_files == {"config/app.yml": "\ntoken: t\n"}
    assert [c.args[3] for c in fetch.call_args_list] == ["app.py"]  # only what was fetched before


async def test_prepare_secrets_scans_the_sparse_files_and_returns_findings_for_the_results():
    key = _key(1)
    scan = await prepare_secrets({"config/app.yml": f"\ntoken: {key}\n"}, RepoConfig())
    assert [(f.file, f.start_line, f.source_tool) for f in scan.findings] == [("config/app.yml", 2, "gitleaks")]


def _secret(file="app.py"):
    return Finding.create(file=file, start_line=1, end_line=1, severity=Severity.CRITICAL, source_tool="gitleaks",
                          rule_id="gitleaks.github-pat", message="Hardcoded secret (github-pat): shape.")


def test_a_secret_finding_never_goes_to_the_fix_agent_even_if_its_file_is_in_state():
    state = {"findings": [_secret()], "repo_level_findings": [], "suppressed_fingerprints": frozenset(),
             "repo_config": RepoConfig(), "files": {"app.py": "TOKEN = 1\n"}, "patches": {},
             "owner": "o", "repo": "r"}
    assert route_after_fanin(state) == "summarize"


async def test_a_failed_scan_is_marked_unavailable_not_raised():
    with patch("codeguard.tools.gitleaks_runner.subprocess.run", side_effect=OSError("no binary")):
        scan = await prepare_secrets({"a.yml": "t: 1\n"}, RepoConfig())
    assert isinstance(scan, SecretScan) and scan.unavailable and scan.findings == []
