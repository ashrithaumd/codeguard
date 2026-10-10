"""Which language a file is, and whether any scanner covers it.

One map, used by PR reviews (diff/filters.py: the reason a changed file was
not reviewed), audits (cli.py: the "Not covered by any scanner" list) and
the PR summary's one line. It is what makes "Files not reviewed" accurate:
a file is listed by its language, so the reader sees the real coverage
instead of one catch-all reason.

COVERED_LANGUAGES grows as scanners are added for a language. A language in
the map but not covered is reported as "Not covered by any scanner
(<language>)" -- including Ruby and PHP, deferred for want of a
permissively licensed rule pack. A file that is not in the map at all is
"not source code" (data, images, build files).
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable

from codeguard.config import RepoConfig

# Python by CodeGuard's own pipeline; the rest through the generic path
# (tools/generic.run_generic_scanners: the vendored GitLab rules and our own
# rules_lang/, including the Dockerfile rules, plus zizmor for GitHub
# Actions) and the security_generic verdict agent.
COVERED_LANGUAGES: frozenset[str] = frozenset({
    "Python", "JavaScript", "TypeScript", "Go", "Java", "C#", "Dockerfile", "GitHub Actions",
})
# Everything covered that is not Python: collected, capped and triaged
# together (cli._collect_generic_files, diff/ingest.py).
GENERIC_LANGUAGES: frozenset[str] = COVERED_LANGUAGES - {"Python"}

_EXTENSIONS = {
    ".py": "Python",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".go": "Go",
    ".java": "Java",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".kt": "Kotlin", ".kts": "Kotlin",
    ".swift": "Swift",
    ".rs": "Rust",
    ".scala": "Scala",
    ".c": "C", ".h": "C",
    ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++",
    ".sh": "Shell", ".bash": "Shell",
    ".tf": "Terraform",
    ".yml": "YAML", ".yaml": "YAML",
}

NOT_COVERED_PREFIX = "Not covered by any scanner"
NOT_SOURCE = "not source code"


def language_of(path: str) -> str | None:
    path = path.replace("\\", "/")
    name = path.rsplit("/", 1)[-1]
    if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return "Dockerfile"
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext in (".yml", ".yaml") and fnmatch.fnmatch(path, ".github/workflows/*"):
        return "GitHub Actions"
    return _EXTENSIONS.get(ext)


def coverage_reason(path: str) -> str | None:
    """Why a file is not reviewed on account of its type, or None when a
    scanner covers it."""
    language = language_of(path)
    if language is None:
        return NOT_SOURCE
    if language in COVERED_LANGUAGES:
        return None
    return f"{NOT_COVERED_PREFIX} ({language})"


def not_covered(paths: Iterable[str], repo_config: RepoConfig) -> list[dict]:
    """[{language, paths}] for every source file no scanner covers, sorted
    by language and path. Lockfiles, generated, docs, vendored files and
    .codeguard.yml ignored_paths are left out, as they are everywhere else."""
    from codeguard.diff.filters import BUILTIN_IGNORED_PATTERNS

    groups: dict[str, list[str]] = {}
    for path in paths:
        if any(fnmatch.fnmatch(path, p) for p in BUILTIN_IGNORED_PATTERNS):
            continue
        if any(fnmatch.fnmatch(path, p) for p in repo_config.ignored_paths):
            continue
        language = language_of(path)
        if language is None or language in COVERED_LANGUAGES:
            continue
        groups.setdefault(language, []).append(path)
    return [{"language": lang, "paths": sorted(ps)} for lang, ps in sorted(groups.items())]


def summary_line(gaps: dict[str, int]) -> str | None:
    """The PR summary's one line: "Not covered by any scanner: Go 3, Kotlin 1."
    None when there is nothing to say."""
    if not gaps:
        return None
    return f"{NOT_COVERED_PREFIX}: " + ", ".join(f"{lang} {n}" for lang, n in sorted(gaps.items())) + "."
