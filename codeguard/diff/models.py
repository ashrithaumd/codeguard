from __future__ import annotations

from pydantic import BaseModel, Field


class Hunk(BaseModel):
    """One reviewable chunk of a file's diff, expanded to ~30 lines of
    surrounding context (GitHub's own patch only gives ~3). start_line/
    end_line are 1-indexed, inclusive, in the file at head_sha.
    content_hash is what codeguard/pipeline/hunk_cache.py keys stored
    findings on: on synchronize, an unchanged hunk's content_hash is
    unchanged too, so its cached result is reused instead of re-calling
    the LLM.
    """
    path: str
    start_line: int
    end_line: int
    content: str
    content_hash: str


class FilteredFile(BaseModel):
    path: str
    reason: str


class DiffIngestionResult(BaseModel):
    owner: str
    repo: str
    pr_number: int
    files_seen: int
    files_filtered: list[FilteredFile] = Field(default_factory=list)
    hunks: list[Hunk] = Field(default_factory=list)
    budget_exceeded: bool = False
    # Full file content at head_sha, keyed by path, for every kept file
    # that was successfully fetched — populated during hunk-context
    # expansion. The deterministic tool runners reuse this directly
    # rather than re-fetching the same content a second time. A path
    # missing here (vs. present with a falsy value) means the fetch
    # failed and hunk building fell back to patch-only context for that
    # file.
    file_contents: dict[str, str] = Field(default_factory=dict)
    # Each kept file's raw GitHub patch text, keyed by path — needed by
    # the deterministic tool runners to compute exact changed-line
    # ranges (narrower than a Hunk's ~30-line context window) for
    # filtering findings down to what the PR actually touched.
    patches: dict[str, str] = Field(default_factory=dict)
    # requirements.txt/pyproject.toml patch+content, pulled
    # from the raw PR file list separately from `patches`/`file_contents`
    # above — those two only ever hold files that survived filter_files,
    # and a dependency manifest never does (matches the docs "*.txt"
    # pattern, or fails the Python-only extension check). Consumed only
    # by tools/osv_runner.py; never fed into hunk building or AI-aware
    # review, since a version pin isn't reviewable code.
    dependency_patches: dict[str, str] = Field(default_factory=dict)
    dependency_contents: dict[str, str] = Field(default_factory=dict)
    # Every changed NON-Python file with additions, as sparse added-lines
    # content (tools/gitleaks_runner.sparse_from_patch): what the secrets
    # scan reads. Built from the patches GitHub already sent, so no extra
    # fetch; Python files are left to CodeGuard's own credential rules.
    secret_scan_files: dict[str, str] = Field(default_factory=dict)
    # Changed JS/TS, Go, Java and C# files (codeguard/languages.py covers them
    # through the vendored rules): content at head and patch, capped by
    # Settings.generic_scan_files_per_pr. Kept apart from file_contents /
    # patches, which are Python's and feed the Python agents.
    generic_contents: dict[str, str] = Field(default_factory=dict)
    generic_patches: dict[str, str] = Field(default_factory=dict)
    # Changed npm/yarn/pnpm, Go, Maven/Gradle and NuGet lockfiles
    # (tools/osv_scanner_runner.is_osv_lockfile), head path -> base path
    # (they differ only for a rename). Paths only: the worker fetches both
    # copies raw, since a lockfile is often over the contents API's 1 MB.
    # Still filtered from review exactly as before.
    lockfile_paths: dict[str, str] = Field(default_factory=dict)

    @property
    def files_reviewed(self) -> list[str]:
        seen = []
        for h in self.hunks:
            if h.path not in seen:
                seen.append(h.path)
        return seen
