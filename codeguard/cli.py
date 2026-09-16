"""`codeguard audit <repo-url-or-local-path>` — a whole-repo scan built
entirely on top of the existing PR-review pipeline's own pieces:
tools/run_all.py's deterministic runners, tools/osv_runner.py, the
Security/AI-aware verdict agents (nodes.py), and eval_hygiene.py.

No second implementation of any tool runner, verdict agent, or
eval-hygiene check. What's new here is orchestration specific to "a
whole tree, not a PR diff" (cloning/walking a repo, building a
synthetic "every line in this file is the diff" patch so the existing
line-range-filtering machinery is a no-op) and the markdown report
renderer, since a standalone report has no PR to post inline comments
on — summarize()'s own output shape doesn't fit here.

AI involvement is deliberately narrower than a PR review: review_security
runs for every file with Bandit findings (same as PR review, since
generic Python security applies everywhere), review_ai_aware runs only
for files that both touch an LLM SDK import AND have Semgrep findings
(same gating PR review uses). Quality/Test (the two generative,
no-tool-baseline agents) are intentionally NOT run here — fanning them
out per-hunk across an entire repo, rather than one PR's worth of
changed hunks, would be the actual "must not run away" cost risk
audit_max_tokens_ceiling exists to prevent, for findings (naming/
structure nitpicks) that matter far less on code nobody just touched.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests
import yaml

from codeguard.config import Budget, RepoConfig, effective_budget, get_settings
from codeguard.diff.filters import is_dependency_manifest, is_reviewable_path
from codeguard.diff.ingest import apply_file_budget, apply_token_budget
from codeguard.diff.models import Hunk
from codeguard.diff.parse import hash_content
from codeguard.pipeline.eval_hygiene import review_eval_hygiene
from codeguard.pipeline.models import DismissedFinding
from codeguard.pipeline.nodes import _file_touches_ai_markers, review_ai_aware, review_security
from codeguard.severity import Severity
from codeguard.tools.models import Finding
from codeguard.tools.osv_runner import check_dependency_updates
from codeguard.tools.run_all import run_tools_on_files

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("codeguard.audit")

CONFIG_FILENAME = ".codeguard.yml"
GITHUB_ISSUES_URL = "https://api.github.com/repos/{owner}/{repo}/issues"


def _is_remote_url(target: str) -> bool:
    return target.startswith(("http://", "https://", "git@")) or target.endswith(".git")


def _clone_shallow(url: str, dest: Path) -> None:
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True, capture_output=True, text=True, timeout=300,
    )


def _load_local_repo_config(root: Path, settings) -> RepoConfig:
    """Same fallback structure as github/repo_config.py's load_repo_config
    (missing file or invalid YAML -> defaults, never a crashed audit),
    sourced from the local working tree instead of a GitHub API call.

    Falls back to a RepoConfig whose own max_files/max_tokens/wall_clock
    fields equal the audit ceiling, not RepoConfig()'s own PR-oriented
    defaults (15 files / 40k tokens) — those exist to bound ONE PR's
    changed hunks and are far smaller than what a useful whole-repo
    audit needs. effective_budget()'s min(repo, ceiling) would otherwise
    silently let a repo with no .codeguard.yml at all — the common case
    for an arbitrary external repo — collapse the audit ceiling down to
    the PR-review default, defeating the point of having a separate,
    deliberately-sized audit ceiling in the first place. A repo that
    DOES ship its own .codeguard.yml still gets to request tighter
    limits than that, same as it would for a real PR.
    """
    default_for_audit = RepoConfig(
        max_files_per_pr=settings.audit_max_files_ceiling,
        max_tokens_per_pr=settings.audit_max_tokens_ceiling,
        max_wall_clock_s=settings.audit_max_wall_clock_s_ceiling,
    )
    config_path = root / CONFIG_FILENAME
    if not config_path.exists():
        return default_for_audit
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        logger.warning("%s exists but isn't valid YAML, using audit defaults", config_path, exc_info=True)
        return default_for_audit
    try:
        return RepoConfig(**data)
    except Exception:
        logger.warning("%s failed validation, using audit defaults: %r", config_path, data, exc_info=True)
        return default_for_audit


def _synthetic_whole_file_patch(content: str) -> str:
    """A unified-diff header claiming every line of `content` was just
    added, nothing else — diff/parse.py's build_hunks and
    tools/line_filter.py's changed-line filtering only ever read the
    `@@ -a,b +c,d @@` header line itself (see parse_hunk_ranges), so
    this is the minimal input needed to make "the whole file is in
    scope" fall out of the exact same code path a real PR diff uses,
    with zero special-casing in either of those two modules.
    """
    line_count = max(len(content.splitlines()), 1)
    return f"@@ -0,0 +1,{line_count} @@"


def _collect_repo_files(
    root: Path, repo_config: RepoConfig,
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Walks the working tree once, classifying every file the same way
    diff/filters.py classifies a PR's changed files (is_reviewable_path,
    is_dependency_manifest) — just against every file on disk instead of
    a GitHub-provided changed-file list, since a full audit has no
    concept of "changed."

    Returns (files, dependency_contents, dependency_patches): `files`
    feeds the deterministic tool runners and the verdict agents;
    the dependency_* pair feeds tools/osv_runner.py exactly the shape
    diff/ingest.py builds for a real PR.
    """
    files: dict[str, str] = {}
    dependency_contents: dict[str, str] = {}
    dependency_patches: dict[str, str] = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in filenames:
            abs_path = Path(dirpath) / name
            rel_path = abs_path.relative_to(root).as_posix()

            # Classify by path FIRST, before ever touching disk — a
            # vendored/lockfile/generated tree can be large, and reading
            # its content only to immediately discard it every time
            # would waste real I/O on every audit run for no benefit.
            is_manifest = is_dependency_manifest(rel_path)
            if not is_manifest and not is_reviewable_path(rel_path, repo_config):
                continue

            try:
                content = abs_path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue  # binary or unreadable — same as GitHub giving us no patch for it

            if is_manifest:
                dependency_contents[rel_path] = content
                dependency_patches[rel_path] = _synthetic_whole_file_patch(content)
            else:
                files[rel_path] = content

    return files, dependency_contents, dependency_patches


def _run_security_verdicts(owner: str, repo: str, files: dict[str, str], tool_findings: list[Finding]):
    """Mirrors route_to_security_reviews + review_security exactly (see
    nodes.py) — every file with at least one Bandit finding, no
    touches_ai_code gate, called directly rather than through the
    graph's Send fan-out (audit has no per-PR graph invocation to hang
    this off of; the node function itself is the reusable unit).
    """
    confirmed: list[Finding] = []
    dismissed: list[DismissedFinding] = []
    tokens_in = tokens_out = 0
    cost = 0.0
    for path, content in files.items():
        bandit_findings = [f for f in tool_findings if f.file == path and f.source_tool == "bandit"]
        if not bandit_findings:
            continue
        result = review_security({
            "owner": owner, "repo": repo, "path": path, "content": content,
            "findings": bandit_findings, "hunk_cache_hits": {},
        })
        confirmed.extend(result.get("findings", []))
        dismissed.extend(result.get("dismissed_findings", []))
        tokens_in += result.get("tokens_in", 0)
        tokens_out += result.get("tokens_out", 0)
        cost += result.get("estimated_cost_usd", 0.0)
    return confirmed, dismissed, tokens_in, tokens_out, cost


def _run_ai_aware_verdicts(owner: str, repo: str, files: dict[str, str], tool_findings: list[Finding]):
    """Mirrors route_to_ai_aware_reviews + review_ai_aware — only files
    that both touch an LLM SDK import AND have Semgrep findings, per
    this module's own docstring on AI-involvement scope.
    """
    confirmed: list[Finding] = []
    dismissed: list[DismissedFinding] = []
    tokens_in = tokens_out = 0
    cost = 0.0
    for path, content in files.items():
        if not _file_touches_ai_markers(content):
            continue
        semgrep_findings = [f for f in tool_findings if f.file == path and f.source_tool == "semgrep"]
        if not semgrep_findings:
            continue
        result = review_ai_aware({
            "owner": owner, "repo": repo, "path": path, "content": content,
            "findings": semgrep_findings, "hunk_cache_hits": {},
        })
        confirmed.extend(result.get("findings", []))
        dismissed.extend(result.get("dismissed_findings", []))
        tokens_in += result.get("tokens_in", 0)
        tokens_out += result.get("tokens_out", 0)
        cost += result.get("estimated_cost_usd", 0.0)
    return confirmed, dismissed, tokens_in, tokens_out, cost


def _severity_label(sev: Severity) -> str:
    return sev.name.capitalize()


def render_report(
    *, target: str, files_scanned: int, files_ai_aware: int,
    ai_reviewed_findings: list[Finding], passthrough_findings: list[Finding],
    dismissed: list[DismissedFinding], eval_hygiene_findings: list[Finding],
    osv_findings: list[Finding], budget_exceeded: bool,
    tokens_in: int, tokens_out: int, estimated_cost_usd: float, elapsed_s: float,
) -> str:
    all_findings = ai_reviewed_findings + passthrough_findings + eval_hygiene_findings + osv_findings
    by_severity: dict[Severity, list[Finding]] = {}
    for f in all_findings:
        by_severity.setdefault(f.severity, []).append(f)

    lines = [f"# CodeGuard audit: {target}", ""]
    lines.append(
        f"{len(all_findings)} finding(s) across {files_scanned} scanned file(s) "
        f"({files_ai_aware} with an LLM SDK import, reviewed for AI-aware issues). "
        f"{len(dismissed)} tool finding(s) reviewed and dismissed by an AI agent as false positives."
    )
    if budget_exceeded:
        lines.append("")
        lines.append(
            "**Note:** this repo exceeded the audit budget ceiling — some files/content "
            "were dropped before review. Findings below are only for what was scanned."
        )
    lines.append("")

    lines.append("## Findings by severity")
    lines.append("")
    for sev in sorted(by_severity, reverse=True):
        findings = sorted(by_severity[sev], key=lambda f: (f.file, f.start_line))
        lines.append(f"### {_severity_label(sev)} ({len(findings)})")
        lines.append("")
        for f in findings:
            lines.append(f"- `{f.file}:{f.start_line}` [{f.source_tool}/{f.rule_id}] {f.message}")
        lines.append("")

    if not all_findings:
        lines.append("No findings.")
        lines.append("")

    if dismissed:
        lines.append("## Dismissed (reviewed by an AI agent, judged not a real issue)")
        lines.append("")
        for d in dismissed:
            lines.append(f"- `{d.file}:{d.start_line}` [{d.rule_id}] {d.reason}")
        lines.append("")

    lines.append("## Eval hygiene")
    lines.append("")
    if eval_hygiene_findings:
        for f in eval_hygiene_findings:
            lines.append(f"- `{f.file}`: {f.message}")
    else:
        lines.append("No eval-hygiene issues found.")
    lines.append("")

    lines.append("## Cost")
    lines.append("")
    lines.append(f"- Tokens: {tokens_in} in / {tokens_out} out")
    lines.append(f"- Estimated cost: ${estimated_cost_usd:.4f}")
    lines.append(f"- Wall clock: {elapsed_s:.1f}s")
    lines.append("")

    return "\n".join(lines)


def post_issue(token: str, owner: str, repo: str, report_markdown: str) -> str:
    resp = requests.post(
        GITHUB_ISSUES_URL.format(owner=owner, repo=repo),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"title": "CodeGuard audit report", "body": report_markdown},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["html_url"]


def _parse_owner_repo(url: str) -> tuple[str, str] | None:
    """Best-effort owner/repo extraction from a GitHub URL, for
    --post-issue. Returns None for anything not recognizably a GitHub
    URL (a local path, a non-GitHub git host) — --post-issue then fails
    with a clear message rather than guessing.
    """
    cleaned = url.removesuffix(".git")
    for prefix in ("https://github.com/", "http://github.com/", "git@github.com:"):
        if cleaned.startswith(prefix):
            rest = cleaned[len(prefix):]
            parts = rest.split("/")
            if len(parts) >= 2:
                return parts[0], parts[1]
    return None


def run_audit(target: str, output_path: str, post_issue_flag: bool) -> int:
    settings = get_settings()
    start = time.monotonic()

    tmp_dir: str | None = None
    try:
        if _is_remote_url(target):
            tmp_dir = tempfile.mkdtemp(prefix="codeguard-audit-")
            print(f"Cloning {target}...", file=sys.stderr)
            try:
                _clone_shallow(target, Path(tmp_dir))
            except subprocess.CalledProcessError as e:
                print(f"git clone failed: {e.stderr}", file=sys.stderr)
                return 1
            root = Path(tmp_dir)
        else:
            root = Path(target).resolve()
            if not root.is_dir():
                print(f"{target} is not a directory and not a recognizable git URL", file=sys.stderr)
                return 1

        repo_config = _load_local_repo_config(root, settings)
        ceiling = Budget(
            max_files=settings.audit_max_files_ceiling,
            max_tokens=settings.audit_max_tokens_ceiling,
            max_wall_clock_s=settings.audit_max_wall_clock_s_ceiling,
        )
        budget = effective_budget(repo_config, settings, ceiling=ceiling)

        all_files, dependency_contents, dependency_patches = _collect_repo_files(root, repo_config)
        print(f"{len(all_files)} reviewable file(s) found.", file=sys.stderr)

        as_file_list = [{"filename": p, "additions": len(c.splitlines())} for p, c in all_files.items()]
        kept_list, _dropped, file_budget_exceeded = apply_file_budget(as_file_list, budget)
        kept_paths = {f["filename"] for f in kept_list}
        files = {p: c for p, c in all_files.items() if p in kept_paths}

        hunks = [
            Hunk(path=p, start_line=1, end_line=max(len(c.splitlines()), 1), content=c, content_hash=hash_content(c))
            for p, c in files.items()
        ]
        selected_hunks, _dropped_hunks, token_budget_exceeded = apply_token_budget(hunks, budget)
        selected_paths = {h.path for h in selected_hunks}
        files = {p: c for p, c in files.items() if p in selected_paths}
        budget_exceeded = file_budget_exceeded or token_budget_exceeded

        synthetic_patches = {p: _synthetic_whole_file_patch(c) for p, c in files.items()}

        tool_findings = asyncio.run(run_tools_on_files(files, synthetic_patches))
        osv_findings = check_dependency_updates(dependency_contents, dependency_patches)
        # Eval hygiene is a pure heuristic (no LLM, no subprocess) — cheap
        # enough to run over every reviewable file regardless of the
        # file/token budget that bounds the (real-cost) tool-runner and
        # verdict-agent calls above. Scoping it to the same budget-
        # trimmed `files` would starve it of visibility into the rest of
        # the repo purely because a couple of large files ate the token
        # ceiling first — a real gap found via this phase's own live
        # verification against simonw/llm (see evals/RESULTS.md).
        eval_hygiene_findings = review_eval_hygiene(all_files) if repo_config.enable_ai_aware else []

        sec_confirmed, sec_dismissed, sec_ti, sec_to, sec_cost = _run_security_verdicts("audit", root.name, files, tool_findings)

        files_ai_aware = sum(1 for c in files.values() if _file_touches_ai_markers(c))
        if repo_config.enable_ai_aware:
            aa_confirmed, aa_dismissed, aa_ti, aa_to, aa_cost = _run_ai_aware_verdicts("audit", root.name, files, tool_findings)
        else:
            aa_confirmed, aa_dismissed, aa_ti, aa_to, aa_cost = [], [], 0, 0, 0.0

        ai_reviewed_findings = sec_confirmed + aa_confirmed
        # Passthrough: every tool finding not claimed by a verdict agent above.
        # Bandit findings are always claimed when present (review_security has
        # no touches_ai_code gate). Semgrep findings are claimed only on files
        # that both touch an AI marker and had enable_ai_aware on. Ruff
        # findings are never claimed by any verdict agent and always pass
        # through raw — same three rules route_to_file_reviews applies for a
        # real PR (nodes.py).
        claimed_bandit_files = {f.file for f in tool_findings if f.source_tool == "bandit"}
        claimed_semgrep_files = {
            f.file for f in tool_findings
            if f.source_tool == "semgrep" and repo_config.enable_ai_aware and _file_touches_ai_markers(files.get(f.file, ""))
        }
        passthrough_findings = [
            f for f in tool_findings
            if not (f.source_tool == "bandit" and f.file in claimed_bandit_files)
            and not (f.source_tool == "semgrep" and f.file in claimed_semgrep_files)
        ]

        dismissed = sec_dismissed + aa_dismissed
        tokens_in = sec_ti + aa_ti
        tokens_out = sec_to + aa_to
        estimated_cost_usd = sec_cost + aa_cost
        elapsed_s = time.monotonic() - start

        report = render_report(
            target=target, files_scanned=len(files), files_ai_aware=files_ai_aware,
            ai_reviewed_findings=ai_reviewed_findings, passthrough_findings=passthrough_findings,
            dismissed=dismissed, eval_hygiene_findings=eval_hygiene_findings, osv_findings=osv_findings,
            budget_exceeded=budget_exceeded, tokens_in=tokens_in, tokens_out=tokens_out,
            estimated_cost_usd=estimated_cost_usd, elapsed_s=elapsed_s,
        )

        Path(output_path).write_text(report, encoding="utf-8")
        print(f"Report written to {output_path}", file=sys.stderr)
        print(f"Cost: ${estimated_cost_usd:.4f}, {tokens_in} in / {tokens_out} out tokens, {elapsed_s:.1f}s", file=sys.stderr)

        if post_issue_flag:
            owner_repo = _parse_owner_repo(target)
            if owner_repo is None:
                print("--post-issue requires a github.com URL target; skipping", file=sys.stderr)
            else:
                token = os.environ.get("GITHUB_TOKEN", "")
                if not token:
                    print("--post-issue requires a GITHUB_TOKEN environment variable; skipping", file=sys.stderr)
                else:
                    owner, repo = owner_repo
                    url = post_issue(token, owner, repo, report)
                    print(f"Issue posted: {url}", file=sys.stderr)

        return 0
    finally:
        if tmp_dir is not None:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codeguard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    audit_parser = subparsers.add_parser("audit", help="Scan a whole repo (URL or local path) and write a markdown report.")
    audit_parser.add_argument("target", help="Git URL (https://... or git@...) or a local directory path")
    audit_parser.add_argument("--output", default="codeguard-audit-report.md", help="Path to write the markdown report to")
    audit_parser.add_argument("--post-issue", action="store_true", help="Also post the report as a GitHub Issue (requires GITHUB_TOKEN env var, github.com targets only)")

    args = parser.parse_args(argv)
    if args.command == "audit":
        return run_audit(args.target, args.output, args.post_issue)
    return 1


if __name__ == "__main__":
    sys.exit(main())
