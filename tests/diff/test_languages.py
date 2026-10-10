"""Per-language coverage (codeguard/languages.py).

"Files not reviewed" used to say "non-Python (v1 scope is Python-only)" for
every other file. It now says which language each file is and that no
scanner covers it, so the reader sees the real coverage: "Not covered by
any scanner (Go)". Files that are not source code say so instead.

Python handling does not change: .py files are reviewed exactly as before.
Ruby and PHP are deliberately not covered (no permissively licensed rule
pack) and are listed like any other uncovered language.
"""

from __future__ import annotations

import pytest

from codeguard.config import RepoConfig
from codeguard.diff.filters import filter_files
from codeguard.languages import COVERED_LANGUAGES, coverage_reason, language_of, not_covered


@pytest.mark.parametrize("path, language", [
    ("app.py", "Python"),
    ("src/server.ts", "TypeScript"), ("ui/App.tsx", "TypeScript"),
    ("index.js", "JavaScript"), ("lib/a.mjs", "JavaScript"), ("lib/b.cjs", "JavaScript"), ("ui/App.jsx", "JavaScript"),
    ("cmd/main.go", "Go"),
    ("src/Main.java", "Java"),
    ("Program.cs", "C#"),
    ("app/models/user.rb", "Ruby"),
    ("index.php", "PHP"),
    ("Main.kt", "Kotlin"), ("App.swift", "Swift"), ("lib.rs", "Rust"), ("Main.scala", "Scala"),
    ("a.c", "C"), ("a.h", "C"), ("a.cpp", "C++"), ("a.hpp", "C++"),
    ("Dockerfile", "Dockerfile"), ("docker/api.Dockerfile", "Dockerfile"), ("Dockerfile.prod", "Dockerfile"),
    (".github/workflows/ci.yml", "GitHub Actions"), (".github/workflows/release.yaml", "GitHub Actions"),
    ("deploy/k8s.yaml", "YAML"), ("config.yml", "YAML"),
    ("scripts/build.sh", "Shell"),
    ("infra/main.tf", "Terraform"),
    ("data.json", None), ("logo.png", None), ("Makefile", None), ("app.pyi", None),
])
def test_language_of(path, language):
    assert language_of(path) == language


def test_covered_languages():
    assert COVERED_LANGUAGES == frozenset({"Python", "JavaScript", "TypeScript", "Go", "Java", "C#"})


def test_coverage_reason():
    assert coverage_reason("cmd/main.go") is None
    assert coverage_reason("Main.kt") == "Not covered by any scanner (Kotlin)"
    assert coverage_reason("index.php") == "Not covered by any scanner (PHP)"
    assert coverage_reason("logo.png") == "not source code"
    assert coverage_reason("app.py") is None


def test_not_covered_groups_by_language_and_leaves_out_python_docs_and_ignored_paths():
    paths = ["app.py", "cmd/main.go", "pkg/util.go", "web/index.ts", "README.md", "notes.txt",
             "node_modules/x/index.js", "vendor/y.go", "app/user.rb", "logo.png", "skip/me.go"]
    groups = not_covered(paths, RepoConfig(ignored_paths=["skip/*"]))
    assert groups == [{"language": "Ruby", "paths": ["app/user.rb"]}]


def test_not_covered_is_empty_for_a_python_only_repo():
    assert not_covered(["a.py", "b/c.py", "README.md", "requirements.txt"], RepoConfig()) == []


# --------------------------------------------------------------------------
# PR reviews: the reason recorded for each filtered file
# --------------------------------------------------------------------------

def _file(name, additions=1):
    return {"filename": name, "additions": additions, "patch": "@@ -1 +1 @@\n+x"}


def test_a_changed_kotlin_file_says_which_language_no_scanner_covers():
    kept, filtered = filter_files([_file("App.kt")], RepoConfig())
    assert kept == [] and [(f.path, f.reason) for f in filtered] == [("App.kt", "Not covered by any scanner (Kotlin)")]


def test_a_changed_go_file_is_neither_a_python_file_nor_not_reviewed():
    """Covered by the vendored rules: reviewed by its own path (diff/ingest),
    never handed to the Python agents, never listed as not reviewed."""
    kept, filtered = filter_files([_file("cmd/main.go"), _file("web/a.ts")], RepoConfig())
    assert kept == [] and filtered == []


def test_a_changed_non_source_file_says_so():
    _, filtered = filter_files([_file("data.json")], RepoConfig())
    assert [f.reason for f in filtered] == ["not source code"]


def test_python_and_the_other_reasons_are_unchanged():
    kept, filtered = filter_files(
        [_file("app.py"), _file("README.md"), _file("gone.py", additions=0), _file("pyproject.toml")], RepoConfig())
    assert [f["filename"] for f in kept] == ["app.py"]
    assert [(f.path, f.reason) for f in filtered] == [
        ("README.md", "lockfile/generated/docs/vendored"),
        ("gone.py", "pure deletion"),
        ("pyproject.toml", "not source code"),
    ]
