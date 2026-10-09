"""Small, pure presentation helpers for the dashboard templates.

Each one is registered as a Jinja filter or global in routes/dashboard.py,
and each one is deliberately done in CODE rather than asked of a model or
left to a template: titles come back from the model in whatever case it
chose, links are built from repository-controlled file paths, and counts
come from stored reports of two different vintages.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
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


# --------------------------------------------------------------------------
# Dismissals, grouped
# --------------------------------------------------------------------------

def _locations(items: list[tuple[str, int]]) -> str:
    """"worker/main.py:98, 103" -- each file once, its lines in order, files
    in the order they first appear."""
    by_file: dict[str, list[int]] = {}
    for file, line in items:
        by_file.setdefault(file, []).append(line)
    return ", ".join(
        f"{file}:{', '.join(str(n) for n in sorted(set(lines)))}" for file, lines in by_file.items()
    )


def group_dismissed(dismissed: list[dict]) -> list[dict]:
    """One row per (rule_id, reason): a verdict is one per rule, so one
    reason usually covers several lines, and listing it once per line
    repeated the same paragraph four times (codeguard-playground's keys)."""
    groups: dict[tuple[str, str], list[tuple[str, int]]] = {}
    for d in dismissed:
        groups.setdefault((d["rule_id"], d["reason"]), []).append((d["file"], d["start_line"]))
    return [
        {"rule_id": rule_id, "reason": reason, "locations": _locations(items), "count": len(items)}
        for (rule_id, reason), items in groups.items()
    ]


# --------------------------------------------------------------------------
# Ruff rule docs
# --------------------------------------------------------------------------

_RUFF_RULES_FILE = Path(__file__).with_name("ruff_rules.json")


@lru_cache(maxsize=1)
def ruff_rule_names() -> dict[str, str]:
    """Code -> rule name, as `ruff rule --all` printed it for the pinned ruff
    (ruff_rules.json; a test compares it with the installed ruff)."""
    return json.loads(_RUFF_RULES_FILE.read_text(encoding="utf-8"))["rules"]


def ruff_docs_url(code: str) -> str | None:
    """https://docs.astral.sh/ruff/rules/<name>/, or None for a code this
    ruff does not know -- no link rather than a guessed one."""
    name = ruff_rule_names().get(code)
    return f"https://docs.astral.sh/ruff/rules/{name}/" if name else None


def repeats_title(finding: dict) -> bool:
    """True when a finding's What says nothing its title does not: ruff's
    message IS its title, so the card showed it twice."""
    def norm(s: str) -> str:
        return re.sub(r"\s+", " ", (s or "").strip().rstrip(".")).lower()
    return bool(finding.get("what")) and norm(finding["what"]) == norm(finding.get("title", ""))


# --------------------------------------------------------------------------
# Low findings, grouped by rule
# --------------------------------------------------------------------------

def _group_title(rule: str, items: list[dict]) -> str:
    """A title that is true of every member. When the members' own titles
    differ -- twelve F841s each naming a different variable -- one of them
    is NOT the group's title: a ruff rule is named by its rule name
    ("unused-variable" -> "Unused variable"), anything else by its first
    title marked as standing for the rest."""
    titles = {i["title"] for i in items}
    if len(titles) == 1:
        return items[0]["title"]
    name = ruff_rule_names().get(rule) if items[0].get("source_tool") == "ruff" else None
    if name:
        return name.replace("-", " ").capitalize()
    return f"{items[0]['title']} (and {len(items) - 1} similar)"


def group_lows(findings: list[dict]) -> list[dict]:
    """The card list, with Low findings that share a rule_id folded into one
    entry: {"group": False, "f": finding} or {"group": True, "rule", "title",
    "members"}. Critical/High/Medium are never grouped -- each is worth its own
    card -- and a Low with no sibling stays a card. Order is kept: a group
    sits where its first member was."""
    low_rules: dict[str, list[dict]] = {}
    for f in findings:
        if f["severity"] == "low":
            low_rules.setdefault(f["rules"][0], []).append(f)
    out: list[dict] = []
    placed: set[str] = set()
    for f in findings:
        rule = f["rules"][0]
        if f["severity"] == "low" and len(low_rules[rule]) > 1:
            if rule not in placed:
                placed.add(rule)
                items = low_rules[rule]
                out.append({"group": True, "rule": rule, "title": _group_title(rule, items), "members": items})
            continue
        out.append({"group": False, "f": f})
    return out
