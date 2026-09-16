"""Orchestrates diff ingestion for one PR: fetch changed files, filter,
expand hunks with context, enforce budget, record metrics. Ties together
codeguard/github/diff.py (raw API calls) and the rest of codeguard/diff/
(pure domain logic).

Budget application (apply_file_budget, apply_token_budget) is split out
as pure functions — no GitHub calls, no async — specifically so it's
testable against constructed data without hitting the real API. That
split is what made it practical to actually exercise the budget-exceeded
path in tests/diff/test_budget.py, which Phase 3 never did.
"""

from __future__ import annotations

import asyncio
import logging

import tiktoken

from codeguard.config import Budget, RepoConfig, Settings, effective_budget
from codeguard.diff.filters import filter_files, is_dependency_manifest
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

# Bounded concurrency for per-file content fetches — Phase 3 fetched
# these sequentially, which measurably doubled per-job latency even for
# a 2-file test PR (see Phase 3's phase-exit review) and would scale
# linearly, badly, with file count. 5 is a starting point, not derived
# from a specific rate-limit calculation — GitHub's REST API allows far
# more concurrent requests than this per installation; 5 just avoids
# opening dozens of simultaneous connections for a large PR without
# meaningfully slowing down a typical one.
CONTENT_FETCH_CONCURRENCY = 5


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


def apply_file_budget(kept: list[dict], budget: Budget) -> tuple[list[dict], list[FilteredFile], bool]:
    """Drop whole files when there are more than budget.max_files,
    biggest-diff-first kept. Pure — no GitHub calls — so it's directly
    testable against a constructed file list.
    """
    if len(kept) <= budget.max_files:
        return kept, [], False

    ordered = sorted(kept, key=lambda f: -(f.get("additions", 0) + f.get("deletions", 0)))
    survivors, dropped = ordered[:budget.max_files], ordered[budget.max_files:]
    filtered = [FilteredFile(path=f["filename"], reason="dropped by max_files budget") for f in dropped]
    return survivors, filtered, True


def apply_token_budget(hunks: list[Hunk], budget: Budget) -> tuple[list[Hunk], list[FilteredFile], bool]:
    """Drop lowest-priority hunks until total token count fits
    budget.max_tokens. A hunk, not a whole file, is the unit dropped —
    partial-file inclusion under pressure beats none. Pure — no GitHub
    calls, no tokenizer state beyond the module-level encoder — directly
    testable against constructed Hunk objects.
    """
    ordered = sorted(hunks, key=_hunk_priority)
    total_tokens = 0
    selected: list[Hunk] = []
    filtered: list[FilteredFile] = []
    exceeded = False

    for hunk in ordered:
        t = len(_tokenizer.encode(hunk.content))
        if selected and total_tokens + t > budget.max_tokens:
            filtered.append(FilteredFile(path=hunk.path, reason="dropped by max_tokens budget"))
            exceeded = True
            continue
        selected.append(hunk)
        total_tokens += t

    return selected, filtered, exceeded


async def _fetch_file_content(
    semaphore: asyncio.Semaphore, token: str, owner: str, repo: str, path: str, head_sha: str,
) -> tuple[str, str | None]:
    async with semaphore:
        try:
            content = await asyncio.to_thread(get_file_content, token, owner, repo, path, head_sha)
        except Exception:
            logger.exception("failed to fetch content for %s@%s, using patch-only context", path, head_sha)
            content = None
    return path, content


async def ingest_pr_diff(
    token: str,
    owner: str,
    repo: str,
    pr_number: int,
    head_sha: str,
    repo_config: RepoConfig,
    settings: Settings,
) -> DiffIngestionResult:
    budget = effective_budget(repo_config, settings)

    raw_files = await asyncio.to_thread(get_pr_files, token, owner, repo, pr_number)
    files_seen_total.inc(len(raw_files))

    kept, filtered = filter_files(raw_files, repo_config)
    for f in filtered:
        files_filtered_total.labels(reason=f.reason).inc()

    kept, file_budget_filtered, file_budget_exceeded = apply_file_budget(kept, budget)
    filtered.extend(file_budget_filtered)
    for f in file_budget_filtered:
        files_filtered_total.labels(reason=f.reason).inc()

    # Phase 11: requirements.txt/pyproject.toml never survive the filters
    # above (a manifest matches "*.txt" or fails the Python-only check)
    # yet osv_runner.py needs their raw patch — pulled straight from
    # raw_files, independent of `kept`, and never added to `kept` itself
    # so a version pin never becomes an AI-reviewable hunk.
    dependency_files = [
        f for f in raw_files if is_dependency_manifest(f["filename"]) and f.get("patch") is not None
    ]

    # Bounded-concurrent content fetches — see CONTENT_FETCH_CONCURRENCY.
    # Dependency manifests ride along in the same batched fetch rather
    # than a second round-trip.
    fetch_targets = kept + [f for f in dependency_files if f["filename"] not in {k["filename"] for k in kept}]
    semaphore = asyncio.Semaphore(CONTENT_FETCH_CONCURRENCY)
    fetch_results = await asyncio.gather(*(
        _fetch_file_content(semaphore, token, owner, repo, f["filename"], head_sha) for f in fetch_targets
    ))
    all_content_by_path = {path: content for path, content in fetch_results if content is not None}
    # file_contents (the result field) documents "every kept file" —
    # dependency manifests ride the same fetch batch above for
    # efficiency but must not leak into it (they're not AI-reviewable
    # code, and tools/run_all.py's runners would otherwise scan them).
    content_by_path = {path: content for path, content in all_content_by_path.items() if path in {k["filename"] for k in kept}}

    all_hunks: list[Hunk] = []
    for f in kept:
        path = f["filename"]
        all_hunks.extend(build_hunks(path, f["patch"], content_by_path.get(path)))

    selected, token_budget_filtered, token_budget_exceeded = apply_token_budget(all_hunks, budget)
    filtered.extend(token_budget_filtered)
    for f in token_budget_filtered:
        files_filtered_total.labels(reason=f.reason).inc()

    budget_exceeded = file_budget_exceeded or token_budget_exceeded

    result = DiffIngestionResult(
        owner=owner, repo=repo, pr_number=pr_number,
        files_seen=len(raw_files), files_filtered=filtered,
        hunks=selected, budget_exceeded=budget_exceeded,
        file_contents=content_by_path,
        patches={f["filename"]: f["patch"] for f in kept},
        dependency_patches={f["filename"]: f["patch"] for f in dependency_files},
        dependency_contents={
            f["filename"]: all_content_by_path[f["filename"]] for f in dependency_files if f["filename"] in all_content_by_path
        },
    )

    files_reviewed_total.inc(len(result.files_reviewed))
    if budget_exceeded:
        budget_exceeded_total.inc()

    return result
