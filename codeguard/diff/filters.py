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

REVIEWABLE_EXTENSIONS = {".py"}

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

        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        if ext not in REVIEWABLE_EXTENSIONS:
            filtered.append(FilteredFile(path=path, reason="non-Python (v1 scope is Python-only)"))
            continue

        if f.get("patch") is None:
            filtered.append(FilteredFile(path=path, reason="no patch available (binary or too large)"))
            continue

        kept.append(f)

    return kept, filtered
