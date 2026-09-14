"""Orchestrates diff ingestion for one PR: fetch changed files, filter,
expand hunks with context, enforce budget, record metrics. Ties together
codeguard/github/diff.py (raw API calls) and the rest of codeguard/diff/
(pure domain logic).
"""

from __future__ import annotations

import logging

import tiktoken

from codeguard.config import RepoConfig, Settings, effective_budget
from codeguard.diff.filters import filter_files
from codeguard.diff.metrics import (
    budget_exceeded_total,
    files_filtered_total,
    files_reviewed_total,
    files_seen_total,
)
from codeguard.diff.models import DiffIngestionResult, FilteredFile, Hunk
from codeguard.diff.parse import build_hunks
from codeguard.github.diff import get_file_content, get_pr_files

logger = logging.getLogger(__name__)
_tokenizer = tiktoken.get_encoding("cl100k_base")


def _hunk_priority(hunk: Hunk) -> tuple:
    """Same idea as v1's utils_github.py priority sort (main entry
    points > src/lib paths > size), applied per-hunk rather than
    per-file so budget truncation drops the least useful *content*
    first, not arbitrary whole files.
    """
    name = hunk.path.rsplit("/", 1)[-1].lower()
    in_src = hunk.path.startswith("src/") or hunk.path.startswith("lib/")
    is_main = name in {"main.py", "app.py", "__init__.py"}
    return (0 if is_main else 1, 0 if in_src else 1, -(hunk.end_line - hunk.start_line))


def ingest_pr_diff(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    head_sha: str,
    repo_config: RepoConfig,
    settings: Settings,
) -> DiffIngestionResult:
    budget = effective_budget(repo_config, settings)

    raw_files = get_pr_files(token, owner, repo, pr_number)
    files_seen_total.inc(len(raw_files))

    kept, filtered = filter_files(raw_files, repo_config)
    for f in filtered:
        files_filtered_total.labels(reason=f.reason).inc()

    budget_exceeded = False

    # max_files: drop whole files first, biggest-diff-first kept.
    if len(kept) > budget.max_files:
        kept.sort(key=lambda f: -(f.get("additions", 0) + f.get("deletions", 0)))
        dropped, kept = kept[budget.max_files:], kept[:budget.max_files]
        for f in dropped:
            reason = "dropped by max_files budget"
            filtered.append(FilteredFile(path=f["filename"], reason=reason))
            files_filtered_total.labels(reason=reason).inc()
        budget_exceeded = True

    all_hunks: list[Hunk] = []
    for f in kept:
        path = f["filename"]
        try:
            content = get_file_content(token, owner, repo, path, ref=head_sha)
        except Exception:
            logger.exception("failed to fetch content for %s@%s, using patch-only context", path, head_sha)
            content = None
        all_hunks.extend(build_hunks(path, f["patch"], content))

    # max_tokens: drop lowest-priority hunks (not whole files — a hunk
    # is the actual unit of review content, so partial-file inclusion
    # under budget pressure is preferable to none).
    all_hunks.sort(key=_hunk_priority)
    total_tokens = 0
    selected: list[Hunk] = []
    for hunk in all_hunks:
        t = len(_tokenizer.encode(hunk.content))
        if selected and total_tokens + t > budget.max_tokens:
            reason = "dropped by max_tokens budget"
            filtered.append(FilteredFile(path=hunk.path, reason=reason))
            files_filtered_total.labels(reason=reason).inc()
            budget_exceeded = True
            continue
        selected.append(hunk)
        total_tokens += t

    result = DiffIngestionResult(
        owner=owner, repo=repo, pr_number=pr_number,
        files_seen=len(raw_files), files_filtered=filtered,
        hunks=selected, budget_exceeded=budget_exceeded,
    )

    files_reviewed_total.inc(len(result.files_reviewed))
    if budget_exceeded:
        budget_exceeded_total.inc()

    return result
