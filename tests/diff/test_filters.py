"""filter_files' own filtering decisions, plus is_dependency_manifest —
notably that requirements.txt/pyproject.toml never survive filter_files
at all (matches the docs "*.txt" pattern, or fails the Python-only
extension check). That's not a bug: codeguard/diff/ingest.py pulls
dependency manifests out of the raw PR file list separately, before
filter_files runs, specifically because of this.
"""

from __future__ import annotations

from codeguard.config import RepoConfig
from codeguard.diff.filters import filter_files, is_dependency_manifest, is_reviewable_path


def _file(name, additions=5, patch="@@ -1,1 +1,1 @@\n+x"):
    return {"filename": name, "additions": additions, "patch": patch}


def test_is_dependency_manifest_matches_requirements_and_pyproject():
    assert is_dependency_manifest("requirements.txt")
    assert is_dependency_manifest("nested/dir/pyproject.toml")
    assert not is_dependency_manifest("readme.txt")
    assert not is_dependency_manifest("app.py")


def test_filter_files_drops_requirements_txt_as_a_doc_pattern():
    kept, filtered = filter_files([_file("requirements.txt")], RepoConfig())
    assert kept == []
    assert filtered[0].path == "requirements.txt"


def test_filter_files_drops_pyproject_toml_as_non_python():
    kept, filtered = filter_files([_file("pyproject.toml")], RepoConfig())
    assert kept == []
    assert filtered[0].path == "pyproject.toml"


def test_filter_files_keeps_a_normal_python_file():
    kept, filtered = filter_files([_file("app.py")], RepoConfig())
    assert [f["filename"] for f in kept] == ["app.py"]
    assert filtered == []


def test_is_reviewable_path_matches_filter_files_classification():
    cfg = RepoConfig(ignored_paths=["*generated_client*"])
    assert is_reviewable_path("app.py", cfg)
    assert not is_reviewable_path("README.md", cfg)
    assert not is_reviewable_path("vendor/lib.py", cfg)
    assert not is_reviewable_path("generated_client/api.py", cfg)
    assert not is_reviewable_path("requirements.txt", cfg)  # docs pattern; handled separately by is_dependency_manifest
