"""codeguard MCP server — exposes the review pipeline to any MCP client
(Claude Code, Cursor) via two tools, both built entirely on existing
pieces (no second implementation of any tool runner, verdict agent, or
budget/filtering logic):

- review_diff: runs the exact same graph worker/main.py runs for a real
  PR (codeguard.pipeline.graph.review_graph) against the CURRENT repo's
  uncommitted changes (staged, unstaged, AND brand-new untracked files —
  `git diff HEAD` alone misses the last of those), returning findings as
  structured JSON. No GitHub calls, no Postgres — hunk cache and
  fingerprint suppression are simply empty, so every hunk gets a fresh
  LLM call.
- audit_repo: thin wrapper around `codeguard audit` (codeguard/cli.py's
  run_audit), for a whole repo (URL or local path) rather than a diff.

stdio transport only — this is meant to be launched as a subprocess by
an MCP client's own config (see README), not run as a long-lived server.
"""

from __future__ import annotations

import asyncio
import subprocess
import tempfile
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from codeguard.cli import _collect_repo_files, _load_local_repo_config, _synthetic_whole_file_patch, run_audit
from codeguard.config import Budget, effective_budget, get_settings, verify_required_settings
from codeguard.diff.filters import filter_files, is_dependency_manifest
from codeguard.diff.ingest import apply_file_budget, apply_token_budget
from codeguard.diff.parse import build_hunks
from codeguard.pipeline.graph import review_graph
from codeguard.pipeline.models import DismissedFinding
from codeguard.tools.models import Finding
from codeguard.tools.osv_runner import check_dependency_updates
from codeguard.tools.run_all import run_tools_on_files

mcp = MCPServer("codeguard")


class GitError(Exception):
    """Raised for any git subprocess failure in this module (not a git
    repo, git not on PATH, a git command timing out) — caught once at
    _run_review_diff's own top level so review_diff returns a clean
    {"error": ...} result instead of an unhandled subprocess exception
    reaching the MCP client. Found via CodeGuard's own live review of
    one of its own PRs — none of the subprocess.run(..., check=True)
    calls here had anything catching the
    CalledProcessError/FileNotFoundError they can raise.
    """


def _run_git(args: list[str], cwd) -> str:
    try:
        result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=30)
    except FileNotFoundError as e:
        raise GitError("git is not installed or not on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git {' '.join(args)} timed out") from e
    if result.returncode != 0:
        raise GitError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _git_repo_root(repo_path: str | None) -> Path:
    # Validate with a cheap, unambiguous check FIRST (per CodeGuard's
    # own review: B603 flagged the lack of this) — a bare
    # `git rev-parse --show-toplevel` on a non-git directory fails with
    # the same generic "not a git repository" message anyway, but
    # naming the check explicitly here keeps every later git command in
    # this module operating on an already-confirmed-valid repo root.
    _run_git(["rev-parse", "--git-dir"], repo_path)
    return Path(_run_git(["rev-parse", "--show-toplevel"], repo_path).strip())


def _git_changed_paths(repo_root: Path) -> list[tuple[str, bool]]:
    """(path, is_untracked) for every file with an uncommitted change —
    tracked modifications AND brand-new files git status has never seen
    before (a plain `git diff HEAD` only shows the former; a new file
    that hasn't been `git add`-ed yet is invisible to it entirely, and
    "review my current changes" while actively writing new files is the
    common case, not an edge case). Deletions excluded — mirrors
    filter_files' own "pure deletion" check (nothing left on disk to
    review).
    """
    stdout = _run_git(["status", "--porcelain=v1", "--untracked-files=all"], repo_root)
    paths = []
    for line in stdout.splitlines():
        if not line:
            continue
        status, path = line[:2], line[3:]
        if "D" in status:
            continue
        paths.append((path, status == "??"))
    return paths


def _git_file_patch(repo_root: Path, path: str, is_untracked: bool) -> str:
    """A real unified diff against HEAD for a tracked change; a synthetic
    whole-file-added patch (same helper cli.py's audit mode uses) for an
    untracked file, since `git diff` has no HEAD version to diff against."""
    if is_untracked:
        try:
            content = (repo_root / path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return ""
        return _synthetic_whole_file_patch(content)
    return _run_git(["diff", "--unified=3", "HEAD", "--", path], repo_root)


def _ingest_local_diff(repo_root: Path, repo_config, budget: Budget):
    """Same shape as diff/ingest.py's DiffIngestionResult fields, sourced
    from the local git diff instead of the GitHub API — reuses
    filter_files, apply_file_budget/apply_token_budget, is_dependency_manifest
    exactly as ingest.py does; only the fetch mechanism (git subprocess
    vs GitHub REST) differs. Like ingest_pr_diff, apply_token_budget's
    result only determines the reported budget_exceeded flag — files/
    patches are trimmed by the file-count budget only, not further
    narrowed to specific surviving hunks (route_to_quality_reviews and
    friends recompute hunks fresh from patches+files either way).
    """
    raw_files = []
    dependency_files = []
    for path, is_untracked in _git_changed_paths(repo_root):
        patch = _git_file_patch(repo_root, path, is_untracked)
        if not patch:
            continue
        if is_dependency_manifest(path):
            dependency_files.append({"filename": path, "patch": patch})
            continue
        if is_untracked:
            # The synthetic patch is header-only (see cli.py's
            # _synthetic_whole_file_patch) — no "+"-prefixed body lines
            # to count, so filter_files' additions==0 "pure deletion"
            # check would wrongly drop every brand-new file. A new file
            # always has additions; the real file's own line count
            # stands in for what a real git diff would report.
            try:
                additions = max(len((repo_root / path).read_text(encoding="utf-8").splitlines()), 1)
            except (OSError, UnicodeDecodeError):
                continue
        else:
            additions = sum(1 for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++"))
        raw_files.append({"filename": path, "additions": additions, "patch": patch})

    kept, _filtered = filter_files(raw_files, repo_config)
    kept, _ff, file_budget_exceeded = apply_file_budget(kept, budget)

    file_contents: dict[str, str] = {}
    for f in kept + dependency_files:
        try:
            file_contents[f["filename"]] = (repo_root / f["filename"]).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            pass

    all_hunks = [
        h for f in kept for h in build_hunks(f["filename"], f["patch"], file_contents.get(f["filename"]))
    ]
    _selected, _tf, token_budget_exceeded = apply_token_budget(all_hunks, budget)

    files = {f["filename"]: file_contents[f["filename"]] for f in kept if f["filename"] in file_contents}
    patches = {f["filename"]: f["patch"] for f in kept}
    dependency_contents = {f["filename"]: file_contents[f["filename"]] for f in dependency_files if f["filename"] in file_contents}
    dependency_patches = {f["filename"]: f["patch"] for f in dependency_files}

    return files, patches, dependency_contents, dependency_patches, (file_budget_exceeded or token_budget_exceeded)


def _serialize_finding(f: Finding) -> dict:
    return {
        "file": f.file, "start_line": f.start_line, "end_line": f.end_line,
        "severity": f.severity.name, "source_tool": f.source_tool, "rule_id": f.rule_id,
        "message": f.message, "confidence": f.confidence,
    }


def _serialize_dismissed(d: DismissedFinding) -> dict:
    return {"file": d.file, "start_line": d.start_line, "rule_id": d.rule_id, "reason": d.reason}


def _error_result(message: str) -> dict:
    return {
        "error": message, "summary": "", "findings": [], "dismissed_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "budget_exceeded": False,
    }


async def _run_review_diff(repo_path: str | None) -> dict:
    settings = get_settings()
    try:
        repo_root = _git_repo_root(repo_path)
        repo_config = _load_local_repo_config(repo_root, settings)
        budget = effective_budget(repo_config, settings)
        files, patches, dependency_contents, dependency_patches, budget_exceeded = _ingest_local_diff(
            repo_root, repo_config, budget,
        )
    except GitError as e:
        return _error_result(str(e))
    if not files:
        return {
            "summary": "No reviewable changes found (git diff HEAD is empty, or every changed file was filtered out).",
            "findings": [], "dismissed_findings": [], "tokens_in": 0, "tokens_out": 0,
            "estimated_cost_usd": 0.0, "budget_exceeded": False,
        }

    tool_findings, osv_findings = await asyncio.gather(
        run_tools_on_files(files, patches),
        asyncio.to_thread(check_dependency_updates, dependency_contents, dependency_patches),
    )
    base_tree_files = _collect_repo_files(repo_root, repo_config)[0] if repo_config.enable_ai_aware else {}

    initial_state = {
        "owner": "local", "repo": repo_root.name, "pr_number": 0, "head_sha": "", "installation_id": 0,
        "repo_config": repo_config, "files": files, "patches": patches,
        "budget_exceeded": budget_exceeded,
        "tool_findings": tool_findings, "base_tree_files": base_tree_files,
        "hunk_cache_hits": {}, "cache_writes": [], "verdict_call_failures": [],
        "suppressed_fingerprints": frozenset(),
        "touches_ai_code": False,
        "findings": [], "repo_level_findings": list(osv_findings), "dismissed_findings": [], "fix_suggestions": [],
        "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
    }
    final_state = await review_graph.ainvoke(initial_state)

    all_findings = final_state["findings"] + final_state["repo_level_findings"]
    return {
        "summary": final_state["summary"],
        "findings": [_serialize_finding(f) for f in all_findings],
        "dismissed_findings": [_serialize_dismissed(d) for d in final_state["dismissed_findings"]],
        "tokens_in": final_state["tokens_in"], "tokens_out": final_state["tokens_out"],
        "estimated_cost_usd": final_state["estimated_cost_usd"], "budget_exceeded": budget_exceeded,
    }


@mcp.tool()
async def review_diff(repo_path: str | None = None) -> dict:
    """Run CodeGuard's full AI-aware review pipeline against the current
    repo's uncommitted changes (staged, unstaged, and new untracked
    files). Returns findings (security, AI-aware, quality, test
    coverage), dismissed tool findings, and token/cost usage as
    structured JSON.

    repo_path: path to the git repo (defaults to the current working
    directory). Must be inside a git repository.
    """
    return await _run_review_diff(repo_path)


@mcp.tool()
async def audit_repo(target: str, post_issue: bool = False) -> dict:
    """Run a whole-repo CodeGuard audit against `target` (a git URL or a
    local directory path) — deterministic security/lint/dependency-CVE
    scanning plus AI-aware verdicts on files that import an LLM SDK.
    Returns the markdown report content plus a structured summary.

    post_issue: also post the report as a GitHub Issue on `target`
    (requires a GITHUB_TOKEN environment variable already set in this
    process's environment; github.com targets only).
    """
    with tempfile.TemporaryDirectory(prefix="codeguard-mcp-audit-") as tmp:
        output_path = str(Path(tmp) / "report.md")
        exit_code, error = await asyncio.to_thread(run_audit, target, output_path, post_issue)
        if exit_code != 0:
            # Found via CodeGuard's own review of one of its own PRs: an
            # empty report string with no explanation looked like a
            # silent no-op success to a caller — this is a real error
            # object with the actual reason (git clone failed, target
            # isn't a directory or git URL, ...), not a guess.
            return {"exit_code": exit_code, "error": error or "audit failed for an unknown reason", "report_markdown": ""}
        report = Path(output_path).read_text(encoding="utf-8") if Path(output_path).exists() else ""
        return {"exit_code": exit_code, "report_markdown": report}


def main() -> None:
    # Before mcp.run() takes over stdio. The message goes to stderr,
    # which the MCP client surfaces as server output; stdout is the
    # JSON-RPC channel and writing to it would corrupt the protocol.
    verify_required_settings()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
