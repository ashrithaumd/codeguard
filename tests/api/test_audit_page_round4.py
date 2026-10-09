"""Audit page polish, fourth pass. All render-time, so audits recorded before
any of this get it too.

  1. Collapsible sections start collapsed: the server never sends `open`,
     and a nonce'd script closes them on every page show (a browser that
     restores an opened <details> on back/forward does not get to).
  2. Dismissals that share a rule_id and a reason are one row listing every
     location ("worker/main.py:98, 103 · B311 · <reason>").
  3. The Skipped heading says what it holds: "Skipped (83 test asserts)".
  4. A ruff finding whose What only repeats its title hides the What row,
     and links the rule's own docs page.
  5. Low findings that share a rule_id are one collapsible card.
"""

from __future__ import annotations

import json
import re
import subprocess
import uuid
from datetime import datetime, timezone

import pytest

from codeguard.api import audits as audits_mod
from codeguard.api.display import group_dismissed, ruff_docs_url, ruff_rule_names

OWNER = "ashrithaumd"
VIEWER = "ashrithaumd"


def _finding(sev, rule, file, line, title, what=None, tool="ai_aware", **kw):
    return {"severity": sev, "title": title, "file": file, "start_line": line, "end_line": line,
            "source_line": 0, "flow": "", "what": what if what is not None else title, "why": "", "fix": "",
            "message": what if what is not None else title, "rules": [rule], "source_tool": tool,
            "unreviewed": False, **kw}


def _report(findings, dismissed=(), skipped_test_asserts=0, skipped_files=(), failures=()):
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("critical", "high", "medium", "low")}
    return {"version": 1, "target": f"https://github.com/{OWNER}/r",
            "summary": {"files_scanned": 3, "files_ai_aware": 0, "total": len(findings), "counts": counts,
                        "repo_level": 0, "dismissed": len(dismissed), "skipped_test_asserts": skipped_test_asserts,
                        "unreviewed": 0, "verdict_calls_failed": len(failures)},
            "incomplete": [], "findings": findings, "repo_level": [], "dismissed": list(dismissed),
            "skipped_files": list(skipped_files), "verdict_call_failures": list(failures),
            "technical": {"tokens_in": 1, "tokens_out": 1, "estimated_cost_usd": 0.0, "elapsed_s": 1.0, "models": {}}}


async def _page(client, pool, as_principal, report, repo="r"):
    audit_id = uuid.uuid4()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO audits (id, owner, repo, requested_by, private, status, created_at) "
            "VALUES (%s, %s, %s, %s, FALSE, 'running', %s)",
            (audit_id, OWNER, repo, VIEWER, datetime.now(timezone.utc)),
        )
    await audits_mod.finish_audit(pool, audit_id, status="done", report_markdown="# r\n", report_json=report)
    as_principal(VIEWER)
    return client.get(f"/dashboard/audits/{audit_id}").text


# The two real reports these were found on, as stored.
PLAYGROUND_KEY_REASON = ("All four occurrences match the literal placeholder string '[redacted]', which is "
                         "explicitly documented at the top of the file as a fake credential.")
PLAYGROUND_DISMISSED = [
    {"file": "assistant.py", "start_line": n, "rule_id": "llm-hardcoded-api-key", "reason": PLAYGROUND_KEY_REASON}
    for n in (21, 24, 25, 45)
]
RELIQUEUE_DISMISSED = [
    {"file": "worker/main.py", "start_line": 98, "rule_id": "B311", "reason": "Simulation delays only."},
    {"file": "worker/main.py", "start_line": 103, "rule_id": "B311", "reason": "Simulation delays only."},
    {"file": "core/queue.py", "start_line": 36, "rule_id": "B311", "reason": "Jitter for retry backoff."},
]


# --------------------------------------------------------------------------
# 1. Collapsed on load
# --------------------------------------------------------------------------

async def test_no_collapsible_section_is_sent_open(client, pool, as_principal):
    html = await _page(client, pool, as_principal, _report(
        [_finding("low", "F841", "a.py", 1, "x", tool="ruff")],
        dismissed=RELIQUEUE_DISMISSED, skipped_test_asserts=83))

    folds = re.findall(r"<details([^>]*)>", html)
    assert len(folds) >= 4
    assert all("open" not in attrs for attrs in folds)


async def test_a_nonced_script_closes_sections_on_every_page_show(client, pool, as_principal):
    html = await _page(client, pool, as_principal, _report([], dismissed=RELIQUEUE_DISMISSED))
    scripts = re.findall(r'<script nonce="([^"]+)">(.*?)</script>', html, re.S)
    closer = [body for _, body in scripts if "details.fold" in body]
    assert closer, "no script resets the folds"
    assert "pageshow" in closer[0] and ".open = false" in closer[0]


# --------------------------------------------------------------------------
# 2. Dismissals grouped by (rule_id, reason)
# --------------------------------------------------------------------------

def test_the_playground_key_dismissals_are_one_row():
    rows = group_dismissed(PLAYGROUND_DISMISSED)
    assert len(rows) == 1
    assert rows[0]["locations"] == "assistant.py:21, 24, 25, 45"
    assert rows[0]["rule_id"] == "llm-hardcoded-api-key"


def test_reliqueue_b311_is_two_rows():
    rows = group_dismissed(RELIQUEUE_DISMISSED)
    assert [(r["locations"], r["reason"]) for r in rows] == [
        ("worker/main.py:98, 103", "Simulation delays only."),
        ("core/queue.py:36", "Jitter for retry backoff."),
    ]


def test_one_reason_across_files_names_each_file():
    rows = group_dismissed([
        {"file": "a.py", "start_line": 3, "rule_id": "B101", "reason": "r"},
        {"file": "b.py", "start_line": 9, "rule_id": "B101", "reason": "r"},
        {"file": "a.py", "start_line": 1, "rule_id": "B101", "reason": "r"},
    ])
    assert [r["locations"] for r in rows] == ["a.py:1, 3, b.py:9"]


async def test_the_page_renders_grouped_rows_and_keeps_the_count(client, pool, as_principal):
    html = await _page(client, pool, as_principal, _report([], dismissed=RELIQUEUE_DISMISSED))
    section = html[html.index("Dismissed by AI (3)"):]
    section = section[:section.index("</details>")]
    rows = re.findall(r'<li class="dismissed-row">(.*?)</li>', section, re.S)
    assert len(rows) == 2
    assert "worker/main.py:98, 103" in rows[0] and "B311" in rows[0] and "Simulation delays only." in rows[0]


# --------------------------------------------------------------------------
# 3. Skipped heading
# --------------------------------------------------------------------------

async def test_the_skipped_heading_says_what_it_holds(client, pool, as_principal):
    html = await _page(client, pool, as_principal, _report([], skipped_test_asserts=83))
    assert re.search(r"<summary[^>]*>\s*Skipped \(83 test asserts\)\s*</summary>", html)


async def test_the_skipped_heading_lists_every_kind(client, pool, as_principal):
    html = await _page(client, pool, as_principal, _report(
        [], skipped_test_asserts=2,
        skipped_files=[{"path": "big.py", "reason": "dropped by audit_max_files_ceiling"}],
        failures=[{"path": "x.py", "reason": "timeout"}]))
    assert re.search(r"<summary[^>]*>\s*Skipped \(2 test asserts, 1 file, 1 failed AI call\)\s*</summary>", html)


# --------------------------------------------------------------------------
# 4. Ruff: no repeated What; a docs link
# --------------------------------------------------------------------------

def test_the_ruff_map_matches_the_installed_ruff():
    proc = subprocess.run(["ruff", "rule", "--all", "--output-format", "json"], capture_output=True, text=True)
    if proc.returncode != 0:
        pytest.skip("ruff not runnable here")
    live = {r["code"]: r["name"] for r in json.loads(proc.stdout)}
    assert ruff_rule_names() == live


def test_ruff_docs_url():
    assert ruff_docs_url("F841") == "https://docs.astral.sh/ruff/rules/unused-variable/"
    assert ruff_docs_url("E402") == "https://docs.astral.sh/ruff/rules/module-import-not-at-top-of-file/"
    assert ruff_docs_url("XYZ999") is None


async def test_a_ruff_card_hides_a_what_that_repeats_its_title_and_links_the_docs(client, pool, as_principal):
    title = "Local variable `job` is assigned to but never used"
    html = await _page(client, pool, as_principal, _report([
        _finding("medium", "F841", "tests/test_q.py", 138, title, tool="ruff"),
        _finding("medium", "B608", "db.py", 13, "SQL injection", what="email is %-formatted in.", tool="security"),
    ]))
    loc = html.index("tests/test_q.py:138")
    ruff_card = html[html.rindex('<li class="finding-card', 0, loc):html.index("</li>", loc)]
    assert "<dt>What</dt>" not in ruff_card
    assert re.search(r'<a class="rule-docs" href="https://docs.astral.sh/ruff/rules/unused-variable/" '
                     r'target="_blank" rel="noopener noreferrer">Rule docs</a>', ruff_card)
    other = html[html.index("SQL injection"):]
    assert "<dt>What</dt>" in other and "rule-docs" not in other.split("</li>")[0]


async def test_an_unmapped_ruff_code_has_no_docs_link(client, pool, as_principal):
    html = await _page(client, pool, as_principal, _report([
        _finding("medium", "ZZZ9", "a.py", 1, "Something", what="Something else", tool="ruff")]))
    assert "rule-docs" not in html


# --------------------------------------------------------------------------
# 5. Low findings grouped by rule
# --------------------------------------------------------------------------

async def test_low_findings_sharing_a_rule_are_one_collapsible_card(client, pool, as_principal):
    lows = [_finding("low", "F841", f"tests/test_{i}.py", 10 + i, "Local variable is assigned to but never used",
                     tool="ruff") for i in range(7)]
    lone_low = _finding("low", "F401", "tests/x.py", 20, "`pytest` imported but unused", tool="ruff")
    medium = _finding("medium", "E402", "chaos.py", 56, "Module level import not at top of file", tool="ruff")
    medium2 = _finding("medium", "E402", "chaos.py", 57, "Module level import not at top of file", tool="ruff")
    html = await _page(client, pool, as_principal, _report([medium, medium2] + lows + [lone_low]))

    groups = re.findall(r'<details class="finding-card low-group[^"]*">\s*<summary[^>]*>(.*?)</summary>(.*?)</details>',
                        html, re.S)
    assert len(groups) == 1
    summary, body = groups[0]
    assert re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", summary)).strip().endswith(
        "F841 · Local variable is assigned to but never used · 7 locations")
    assert len(re.findall(r'class="finding-loc"', body)) == 7
    # Medium stays individual, even sharing a rule; a lone Low stays a card.
    assert len(re.findall(r'<li class="finding-card sev-edge-medium', html)) == 2
    assert "tests/x.py:20" in html and "low-group" not in html.split("tests/x.py:20")[0].rsplit("<li", 1)[-1]
    # The severity bar still counts every finding.
    assert re.search(r"Low <b>8</b>", html) and re.search(r"Medium <b>2</b>", html)


def test_a_group_whose_titles_differ_is_named_after_the_rule_not_one_member():
    """Live on reliqueue: twelve F841s, each naming a different variable,
    were grouped under "Local variable `reclaimed` is assigned to but never
    used" -- one member's title presented as all of theirs."""
    from codeguard.api.display import group_lows

    lows = [_finding("low", "F841", "t.py", n, f"Local variable `{v}` is assigned to but never used", tool="ruff")
            for n, v in ((1, "reclaimed"), (2, "job"))]
    [group] = group_lows(lows)
    assert group["title"] == "Unused variable"

    same = [_finding("low", "E402", "c.py", n, "Module level import not at top of file", tool="ruff") for n in (1, 2)]
    assert group_lows(same)[0]["title"] == "Module level import not at top of file"

    other = [_finding("low", "X1", "c.py", n, f"Thing {n}", tool="semgrep") for n in (1, 2)]
    assert group_lows(other)[0]["title"] == "Thing 1 (and 1 similar)"
