"""Audits record the files no scanner covers, from a path-only walk.

The walk reads no file content (it is a statement about names), skips .git
and every symlink exactly as the file collection does, and leaves out
lockfiles, generated, docs, vendored files and .codeguard.yml ignored_paths.
The result goes into the report data -- stored as report_json, rendered on
the audit page and in the markdown report -- and is absent from neither.
"""

from __future__ import annotations

import os

import pytest

from codeguard.cli import _not_covered_files, build_report_data, render_report
from codeguard.config import RepoConfig


def _tree(tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


def test_the_walk_groups_uncovered_source_files_by_language(tmp_path):
    root = _tree(tmp_path, {
        "app.py": "x = 1", "cmd/main.go": "package main", "web/index.ts": "export {}",
        "README.md": "#", "node_modules/a/index.js": "", ".git/hooks/x.go": "", "skip/me.go": "",
        "data.json": "{}",
    })
    groups = _not_covered_files(root, RepoConfig(ignored_paths=["skip/*"]))
    assert groups == [{"language": "Go", "paths": ["cmd/main.go"]},
                      {"language": "TypeScript", "paths": ["web/index.ts"]}]


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlinks_are_not_followed_or_listed(tmp_path):
    root = _tree(tmp_path, {"real.go": "package x"})
    (root / "link.go").symlink_to(root / "real.go")
    (root / "linkdir").symlink_to(tmp_path)
    assert _not_covered_files(root, RepoConfig()) == [{"language": "Go", "paths": ["real.go"]}]


def _kwargs(not_covered):
    return dict(
        target="https://github.com/o/r", files_scanned=1, files_ai_aware=0, ai_reviewed_findings=[],
        passthrough_findings=[], dismissed=[], eval_hygiene_findings=[], osv_findings=[], skipped_files=[],
        verdict_call_failures=[], unavailable_tools=[], tokens_in=0, tokens_out=0, estimated_cost_usd=0.0,
        elapsed_s=1.0, not_covered=not_covered)


def _data(not_covered):
    return build_report_data(**_kwargs(not_covered))


def test_the_report_data_carries_the_list_and_a_count():
    data = _data([{"language": "Go", "paths": ["a.go", "b.go"]}])
    assert data["not_covered"] == [{"language": "Go", "paths": ["a.go", "b.go"]}]
    assert data["summary"]["not_covered"] == 2


def test_the_markdown_report_says_so():
    text = render_report(**_kwargs([{"language": "Go", "paths": ["a.go", "b.go"]}]))
    assert "Not covered by any scanner" in text and "Go (2)" in text and "`a.go`" in text


def test_nothing_uncovered_changes_nothing_in_the_markdown():
    assert "Not covered by any scanner" not in render_report(**_kwargs([]))
