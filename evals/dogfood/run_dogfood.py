"""Phase 9 item 3: dogfood — run the real CodeGuard pipeline against
real diffs from the author's own repos, read-only. No PR is opened, no
comment is posted anywhere; this only prints a report.

Both target repos (ashrithaumd/codeguard, ashrithaumd/DocuMind) are
public, and the GitHub App installation doesn't currently cover either
of them (only ashrithaumd/codeguard-playground) — so rather than
requiring the user to change that installation, this sources the diff
from GitHub's public compare API (`base...head`, unauthenticated,
same `files` shape — filename/patch/additions/deletions — the PR-files
endpoint already gives codeguard.diff.ingest) and file content from
raw.githubusercontent.com. Everything downstream of that (filter_files,
apply_file_budget, build_hunks, apply_token_budget, run_tools_on_files,
review_graph) is the exact same code path a live webhook would run.

Usage (needs Semgrep's native engine, Linux-only):
    docker exec codeguard-worker-1 python evals/dogfood/run_dogfood.py
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import requests

from codeguard.config import RepoConfig, get_settings, effective_budget
from codeguard.diff.filters import filter_files
from codeguard.diff.ingest import CONTENT_FETCH_CONCURRENCY, apply_file_budget, apply_token_budget
from codeguard.diff.parse import build_hunks
from codeguard.pipeline.graph import review_graph
from codeguard.tools.run_all import run_tools_on_files

RAW_URL = "https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
COMPARE_URL = "https://api.github.com/repos/{owner}/{repo}/compare/{base}...{head}"


def _fetch_compare_files(owner: str, repo: str, base: str, head: str) -> list[dict]:
    resp = requests.get(COMPARE_URL.format(owner=owner, repo=repo, base=base, head=head), timeout=30)
    resp.raise_for_status()
    return resp.json()["files"]


def _fetch_raw_content(owner: str, repo: str, ref: str, path: str) -> str | None:
    resp = requests.get(RAW_URL.format(owner=owner, repo=repo, ref=ref, path=path), timeout=30)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.text


async def _fetch_all_content(owner: str, repo: str, ref: str, paths: list[str]) -> dict[str, str]:
    semaphore = asyncio.Semaphore(CONTENT_FETCH_CONCURRENCY)

    async def _one(path: str) -> tuple[str, str | None]:
        async with semaphore:
            content = await asyncio.to_thread(_fetch_raw_content, owner, repo, ref, path)
        return path, content

    results = await asyncio.gather(*(_one(p) for p in paths))
    return {path: content for path, content in results if content is not None}


async def dogfood_one_repo(owner: str, repo: str, base: str, head: str, repo_config: RepoConfig | None = None) -> dict:
    repo_config = repo_config or RepoConfig()
    settings = get_settings()
    budget = effective_budget(repo_config, settings)

    raw_files = _fetch_compare_files(owner, repo, base, head)
    kept, filtered = filter_files(raw_files, repo_config)
    kept, file_budget_filtered, file_budget_exceeded = apply_file_budget(kept, budget)
    filtered.extend(file_budget_filtered)

    paths = [f["filename"] for f in kept]
    content_by_path = await _fetch_all_content(owner, repo, head, paths)
    patches = {f["filename"]: f["patch"] for f in kept}

    all_hunks = []
    for f in kept:
        path = f["filename"]
        all_hunks.extend(build_hunks(path, f["patch"], content_by_path.get(path)))

    selected_hunks, token_budget_filtered, token_budget_exceeded = apply_token_budget(all_hunks, budget)
    filtered.extend(token_budget_filtered)
    reviewed_paths = {h.path for h in selected_hunks}
    # Only keep file content/patches for files that survived BOTH budgets
    # — the same scope worker/main.py's diff_result.file_contents ends
    # up with after ingest_pr_diff.
    content_by_path = {p: c for p, c in content_by_path.items() if p in reviewed_paths}
    patches = {p: patch for p, patch in patches.items() if p in reviewed_paths}

    tool_findings = await run_tools_on_files(content_by_path, patches)

    initial_state = {
        "owner": owner, "repo": repo, "pr_number": 0, "head_sha": head, "installation_id": 0,
        "repo_config": repo_config,
        "files": content_by_path, "patches": patches, "tool_findings": tool_findings,
        # Repo-level eval-hygiene needs a base-tree sample fetch this
        # read-only script doesn't do (no PR context to bound it to) —
        # skipped here, noted in the report rather than silently implied.
        "base_tree_files": {},
        "hunk_cache_hits": {}, "cache_writes": [],
        "touches_ai_code": False,
        "findings": [], "repo_level_findings": [], "dismissed_findings": [], "fix_suggestions": [],
        "should_fix": False, "summary": "", "inline_findings": [],
        "tokens_in": 0, "tokens_out": 0, "estimated_cost_usd": 0.0, "node_latencies": [],
    }
    final_state = await review_graph.ainvoke(initial_state)

    return {
        "owner": owner, "repo": repo, "base": base, "head": head,
        "files_in_diff": len(raw_files), "files_reviewed": len(content_by_path),
        "files_filtered": [(f.path, f.reason) for f in filtered],
        "budget_exceeded": file_budget_exceeded or token_budget_exceeded,
        "findings": [
            {"file": f.file, "line": f.start_line, "severity": f.severity.name, "source_tool": f.source_tool,
             "rule_id": f.rule_id, "message": f.message, "confidence": f.confidence}
            for f in (final_state["findings"] + final_state["repo_level_findings"])
        ],
        "dismissed_findings": [
            {"file": d.file, "line": d.start_line, "rule_id": d.rule_id, "reason": d.reason}
            for d in final_state["dismissed_findings"]
        ],
        "inline_findings_count": len(final_state["inline_findings"]),
        "fix_suggestions_count": len(final_state["fix_suggestions"]),
        "tokens_in": final_state["tokens_in"], "tokens_out": final_state["tokens_out"],
        "estimated_cost_usd": final_state["estimated_cost_usd"],
        "latency_s": sum(lat["seconds"] for lat in final_state["node_latencies"]),
        "summary": final_state["summary"],
    }


TARGETS = [
    {"owner": "ashrithaumd", "repo": "codeguard", "base": "main", "head": "v2"},
    {"owner": "ashrithaumd", "repo": "DocuMind", "base": "80ff626fb4", "head": "8f9f031ced"},
]


async def main() -> None:
    results = []
    for target in TARGETS:
        print(f"=== dogfooding {target['owner']}/{target['repo']} ({target['base']}...{target['head']}) ===")
        result = await dogfood_one_repo(**target)
        results.append(result)

        print(f"  files in diff: {result['files_in_diff']}, reviewed: {result['files_reviewed']}, "
              f"budget_exceeded: {result['budget_exceeded']}")
        print(f"  filtered ({len(result['files_filtered'])}): {result['files_filtered'][:10]}"
              f"{'...' if len(result['files_filtered']) > 10 else ''}")
        print(f"  {len(result['findings'])} finding(s), {len(result['dismissed_findings'])} dismissed, "
              f"{result['inline_findings_count']} would be inline, {result['fix_suggestions_count']} fix suggestion(s)")
        for f in result["findings"]:
            print(f"    [{f['severity']}/{f['source_tool']}/conf={f['confidence']:.2f}] {f['file']}:{f['line']} "
                  f"{f['rule_id']}: {f['message']}")
        for d in result["dismissed_findings"]:
            print(f"    DISMISSED [{d['rule_id']}] {d['file']}:{d['line']}: {d['reason']}")
        print(f"  tokens_in={result['tokens_in']} tokens_out={result['tokens_out']} "
              f"cost_usd={result['estimated_cost_usd']:.4f} latency_s={result['latency_s']:.2f}")
        print(f"  summary: {result['summary'][:500]}")
        print()

    out_path = Path(__file__).parent / "dogfood_results.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"wrote raw results to {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
