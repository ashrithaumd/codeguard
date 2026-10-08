"""Small, pure presentation helpers for the dashboard templates.

Each one is registered as a Jinja filter or global in routes/dashboard.py,
and each one is deliberately done in CODE rather than asked of a model or
left to a template: titles come back from the model in whatever case it
chose, links are built from repository-controlled file paths, and counts
come from stored reports of two different vintages.
"""

from __future__ import annotations

import re
from urllib.parse import quote

# --------------------------------------------------------------------------
# Sentence case
# --------------------------------------------------------------------------

# Capitalised words that stay capitalised: product and tool names a model
# writes in titles. Fully-upper words (SQL, LLM, API) need no list -- an
# all-caps word of two or more letters is kept as an acronym.
_PROPER_NOUNS = frozenset({
    "Anthropic", "OpenAI", "Claude", "Python", "GitHub", "Bandit", "Semgrep", "Ruff",
    "LangChain", "LlamaIndex", "Flask", "FastAPI", "Django", "Postgres", "SQLite", "Azure",
})
# A plain capitalised word: one capital, then lower-case letters only.
# Anything else -- eval(), max_tokens, OpenAI, SQL, v2 -- is left alone.
_TITLE_WORD = re.compile(r"^[A-Z][a-z]+$")


def sentence_case(title: str) -> str:
    """'SQL Injection via String Formatting' -> 'SQL injection via string
    formatting'. The first letter is capitalised; later plain capitalised
    words are lowered unless they are proper nouns; acronyms, code and
    mixed-case names are kept as written."""
    if not title:
        return title
    words = title.split(" ")
    out = []
    for i, word in enumerate(words):
        if i > 0 and _TITLE_WORD.match(word) and word not in _PROPER_NOUNS:
            word = word.lower()
        out.append(word)
    first = out[0]
    if first[:1].islower():
        out[0] = first[:1].upper() + first[1:]
    return " ".join(out)


# --------------------------------------------------------------------------
# Links to the audited line
# --------------------------------------------------------------------------

_SHA = re.compile(r"^[0-9a-f]{40}$")
_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")


def blob_url(owner: str, repo: str, sha: str | None, path: str, start: int, end: int) -> str | None:
    """https://github.com/<owner>/<repo>/blob/<sha>/<path>#L<start>[-L<end>],
    or None when any part is not what it should be.

    The path is the repository's own file name -- text its authors chose --
    so it is percent-encoded segment by segment, and refused outright if it
    could climb out of the tree. The sha must be a full lower-case commit
    hash: it is what pins the link to the code that was audited, rather
    than to whatever the branch says today.
    """
    if not sha or not _SHA.match(sha) or not _NAME.match(owner or "") or not _NAME.match(repo or ""):
        return None
    parts = path.replace("\\", "/").split("/")
    if not path or any(p in ("", ".", "..") for p in parts):
        return None
    anchor = f"#L{start}" if not end or end <= start else f"#L{start}-L{end}"
    return f"https://github.com/{owner}/{repo}/blob/{sha}/{quote(path, safe='/')}{anchor}"


# --------------------------------------------------------------------------
# An audit's finding counts
# --------------------------------------------------------------------------

_SEVERITIES = ("critical", "high", "medium", "low")
# Markdown written before report_json existed (cli.render_report, Oct 2026):
# "13 finding(s) across ..." and one "### High (5)" heading per severity.
_LEGACY_TOTAL = re.compile(r"^(\d+) finding\(s\) across", re.M)
_LEGACY_HEADING = re.compile(r"^### (Critical|High|Medium|Low) \((\d+)\)$", re.M)


def finding_counts(audit: dict) -> dict | None:
    """{"total", "counts", "label"} for an audit, or None if it recorded
    none (a failed audit, a sample row without counts).

    report_json when present; otherwise the counts are read back out of the
    markdown this codebase itself wrote for the audits that predate it. The
    label names the most severe buckets: "12 · 1 Critical, 4 High", or the
    single highest bucket when there is nothing critical or high.
    """
    data = audit.get("report_json")
    if isinstance(data, dict) and isinstance(data.get("summary"), dict):
        summary = data["summary"]
        total = int(summary.get("total", 0))
        counts = {s: int(summary.get("counts", {}).get(s, 0)) for s in _SEVERITIES}
    else:
        md = audit.get("report_markdown") or ""
        m = _LEGACY_TOTAL.search(md)
        if not m:
            return None
        total = int(m.group(1))
        counts = dict.fromkeys(_SEVERITIES, 0)
        for name, n in _LEGACY_HEADING.findall(md):
            counts[name.lower()] = int(n)

    shown = [s for s in ("critical", "high") if counts[s]]
    if not shown:
        shown = [s for s in _SEVERITIES if counts[s]][:1]
    parts = [f"{counts[s]} {s.capitalize()}" for s in shown]
    label = f"{total} · {', '.join(parts)}" if parts else str(total)
    return {"total": total, "counts": counts, "label": label}
