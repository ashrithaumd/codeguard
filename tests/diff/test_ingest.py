"""Regression coverage for ingest_pr_diff's own orchestration, GitHub
calls mocked out. Confirms a requirements.txt/pyproject.toml change
reaches DiffIngestionResult's
dependency_patches/dependency_contents even though it's dropped from
`kept`/`patches` by filter_files (see test_filters.py) — without this,
tools/osv_runner.py would silently never see a dependency bump.
"""

from __future__ import annotations

from unittest.mock import patch

from codeguard.config import RepoConfig, get_settings
from codeguard.diff.ingest import ingest_pr_diff

REQUIREMENTS_PATCH = "@@ -1,1 +1,1 @@\n-pyyaml==5.0\n+pyyaml==5.3\n"


def _pr_file(name, additions=1, patch="@@ -1,1 +1,1 @@\n+x"):
    return {"filename": name, "additions": additions, "deletions": 0, "patch": patch}


async def _ingest(raw_files, file_contents):
    with patch("codeguard.diff.ingest.get_pr_files", return_value=raw_files), \
         patch("codeguard.diff.ingest.get_file_content", side_effect=lambda token, o, r, path, sha: file_contents.get(path)):
        return await ingest_pr_diff("tok", "o", "r", 1, "sha", RepoConfig(), get_settings())


async def test_dependency_manifest_patch_and_content_are_captured_separately():
    raw_files = [_pr_file("app.py"), _pr_file("requirements.txt", patch=REQUIREMENTS_PATCH)]
    file_contents = {"app.py": "x = 1\n", "requirements.txt": "pyyaml==5.3\n"}

    result = await _ingest(raw_files, file_contents)

    assert result.dependency_patches == {"requirements.txt": REQUIREMENTS_PATCH}
    assert result.dependency_contents == {"requirements.txt": "pyyaml==5.3\n"}
    # never treated as reviewable code
    assert "requirements.txt" not in result.patches
    assert "requirements.txt" not in result.file_contents
    assert result.files_reviewed == ["app.py"]


async def test_no_dependency_manifest_touched_means_empty_dependency_fields():
    raw_files = [_pr_file("app.py")]
    result = await _ingest(raw_files, {"app.py": "x = 1\n"})

    assert result.dependency_patches == {}
    assert result.dependency_contents == {}


async def test_dependency_manifest_with_no_patch_is_skipped():
    raw_files = [_pr_file("app.py"), {"filename": "requirements.txt", "additions": 1, "deletions": 0, "patch": None}]
    result = await _ingest(raw_files, {"app.py": "x = 1\n"})

    assert result.dependency_patches == {}
