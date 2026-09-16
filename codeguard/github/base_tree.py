"""Fetches a bounded set of base-tree Python file contents for the
repo-level eval-hygiene checks (see codeguard/pipeline/eval_hygiene.py).
Always the PR's base ref, never the head — same reasoning as
repo_config.py's load_repo_config: this describes the target repo's own
practices, not what an untrusted PR head wants them to look like.

Mirrors diff/ingest.py's bounded-concurrency content-fetch pattern
(asyncio.Semaphore + to_thread over the same sync get_file_content), not
reused directly, since this fetches from a repo tree listing rather than
a PR's changed-files list.
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging

from codeguard.github.diff import get_file_content, get_repo_tree

logger = logging.getLogger(__name__)

# One GitHub API call per file below this cap. Eval hygiene is a
# heuristic repo-practice signal, not exhaustive coverage — on a large
# repo, fetching every Python file on every single PR review would let
# this one check dominate a job's wall-clock and GitHub API-call budget
# on its own. Sampling up to this many candidates is a deliberate
# trade-off, not an oversight.
MAX_BASE_TREE_FILES = 60
CONTENT_FETCH_CONCURRENCY = 5

_SKIP_PATTERNS = (
    "*/node_modules/*", "*/vendor/*", "*/.venv/*", "*/venv/*",
    "*_pb2.py", "*/site-packages/*", "*/.git/*",
)


def _is_candidate(path: str) -> bool:
    return path.endswith(".py") and not any(fnmatch.fnmatch(path, p) for p in _SKIP_PATTERNS)


async def _fetch(semaphore: asyncio.Semaphore, token: str, owner: str, repo: str, path: str, ref: str) -> tuple[str, str | None]:
    async with semaphore:
        try:
            content = await asyncio.to_thread(get_file_content, token, owner, repo, path, ref)
        except Exception:
            logger.exception("eval-hygiene: failed to fetch %s@%s, skipping", path, ref)
            content = None
    return path, content


async def fetch_base_tree_python_files(token: str, owner: str, repo: str, base_ref: str) -> dict[str, str]:
    """path -> content for up to MAX_BASE_TREE_FILES Python files at the
    base ref. Best-effort: a tree-listing failure or a per-file fetch
    failure never raises — eval-hygiene is a soft signal on top of the
    review, not something that should fail the whole job.
    """
    try:
        tree = await asyncio.to_thread(get_repo_tree, token, owner, repo, base_ref)
    except Exception:
        logger.exception("eval-hygiene: failed to list repo tree for %s/%s@%s", owner, repo, base_ref)
        return {}

    candidates = [e["path"] for e in tree if _is_candidate(e["path"])][:MAX_BASE_TREE_FILES]

    semaphore = asyncio.Semaphore(CONTENT_FETCH_CONCURRENCY)
    results = await asyncio.gather(*(
        _fetch(semaphore, token, owner, repo, path, base_ref) for path in candidates
    ))
    return {path: content for path, content in results if content is not None}
