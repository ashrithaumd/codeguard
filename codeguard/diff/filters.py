"""File filtering for diff ingestion. Order matters: built-in skip
patterns (lockfiles/generated/docs/vendored) first, then the repo's own
.codeguard.yml ignored_paths, then pure deletions, then language scope
(Python-only for v1 — an explicit project decision, not a guess), then
files GitHub didn't give us a patch for at all (binary or too large).
"""

from __future__ import annotations

import fnmatch

from codeguard.config import RepoConfig
from codeguard.diff.models import FilteredFile
from codeguard.tools.models import Finding

REVIEWABLE_EXTENSIONS = {".py"}

# Dependency manifests are never AI-reviewable code (nothing
# for Quality/Test/Security agents to say about a version pin), but
# tools/osv_runner.py still needs their raw patch — see
# is_dependency_manifest's callers in diff/ingest.py, which pull these
# out of the raw PR file list BEFORE the docs/non-Python filters below
# would otherwise drop requirements.txt (matches "*.txt") and
# pyproject.toml (non-Python extension) on the floor.
DEPENDENCY_MANIFEST_FILENAMES = ("requirements.txt", "pyproject.toml")


def is_dependency_manifest(path: str) -> bool:
    return path.rsplit("/", 1)[-1] in DEPENDENCY_MANIFEST_FILENAMES


BUILTIN_IGNORED_PATTERNS = (
    # Lockfiles
    "*package-lock.json", "*yarn.lock", "*pnpm-lock.yaml", "*poetry.lock",
    "*Pipfile.lock", "*Gemfile.lock", "*go.sum", "*Cargo.lock", "*composer.lock",
    # Generated
    "*.min.js", "*_pb2.py", "*.generated.*", "*dist/*", "*build/*",
    # Docs
    "*.md", "*.rst", "*.txt", "*docs/*",
    # Vendored
    "*vendor/*", "*node_modules/*", "*third_party/*",
)


def _matches_any(path: str, patterns) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def _extension(path: str) -> str:
    """Was duplicated verbatim between is_reviewable_path and
    filter_files (found via CodeGuard's own review of one of its own
    PRs) — extracted once here. No dot in the filename (or the dot is
    part of a directory name, e.g. "a.b/README") means no extension at
    all, not the directory segment's own suffix.
    """
    name = path.rsplit("/", 1)[-1]
    return "." + name.rsplit(".", 1)[-1] if "." in name else ""


def is_reviewable_path(path: str, repo_config: RepoConfig) -> bool:
    """The part of filter_files' classification below that applies to
    any path regardless of context, not just a PR's changed-file list —
    not a builtin-ignored pattern, not repo-config-ignored, and a
    reviewable extension. Used by `codeguard audit` (cli.py) walking a
    full tree, which has no `additions`/`patch` per file to apply
    filter_files' remaining, PR-specific checks against.
    """
    if _matches_any(path, BUILTIN_IGNORED_PATTERNS):
        return False
    if _matches_any(path, repo_config.ignored_paths):
        return False
    return _extension(path) in REVIEWABLE_EXTENSIONS


def filter_files(files: list[dict], repo_config: RepoConfig) -> tuple[list[dict], list[FilteredFile]]:
    """Split GitHub's PR-files list (each a dict with `filename`,
    `additions`, `patch`, etc. — see codeguard/github/diff.py) into
    (kept, filtered), each filtered entry carrying why.
    """
    kept: list[dict] = []
    filtered: list[FilteredFile] = []

    for f in files:
        path = f["filename"]

        if _matches_any(path, BUILTIN_IGNORED_PATTERNS):
            filtered.append(FilteredFile(path=path, reason="lockfile/generated/docs/vendored"))
            continue

        if _matches_any(path, repo_config.ignored_paths):
            filtered.append(FilteredFile(path=path, reason="excluded by .codeguard.yml ignored_paths"))
            continue

        if f.get("additions", 0) == 0:
            filtered.append(FilteredFile(path=path, reason="pure deletion"))
            continue

        if _extension(path) not in REVIEWABLE_EXTENSIONS:
            filtered.append(FilteredFile(path=path, reason="non-Python (v1 scope is Python-only)"))
            continue

        if f.get("patch") is None:
            filtered.append(FilteredFile(path=path, reason="no patch available (binary or too large)"))
            continue

        kept.append(f)

    return kept, filtered


_TEST_DIRS = frozenset({"tests", "test"})


def is_test_path(path: str) -> bool:
    """A test file, judged on path SEGMENTS rather than substrings: any
    directory named tests/ or test/, a test_*.py or *_test.py basename, or
    conftest.py.

    Shared by the audit (B101 suppression and the file-ceiling tiers) and
    eval hygiene. The substring version eval hygiene had matched "test_"
    anywhere -- latest_model.py was a test -- and never matched conftest.py.
    """
    parts = path.replace("\\", "/").lower().split("/")
    name = parts[-1]
    return (
        any(part in _TEST_DIRS for part in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def split_test_asserts(tool_findings: list[Finding]) -> tuple[list[Finding], int]:
    """Bandit's B101 (`assert` is stripped under -O) in a TEST file, taken
    out before the verdict layer and counted rather than judged.

    In a test, an assert is the whole point. On reliqueue 83 of 86
    dismissals were exactly these, and they cost most of that audit's
    $0.066 to have a model say so 83 times. Applied by both the audit
    (cli.run_audit) and the PR review (worker._tool_findings_for_review). B101 anywhere else is kept:
    an assert guarding application logic really does vanish under -O.
    """
    kept: list[Finding] = []
    skipped = 0
    for f in tool_findings:
        if f.source_tool == "bandit" and f.rule_id == "B101" and is_test_path(f.file):
            skipped += 1
        else:
            kept.append(f)
    return kept, skipped
