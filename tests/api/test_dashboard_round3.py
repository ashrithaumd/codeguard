"""Audit and repo page feedback, third pass.

  1. Repo tiles were inconsistent: Total cost included the viewer's audits,
     Findings and Tokens in did not. Every tile now includes them, with a
     reviews/audits breakdown under each figure.
  2. The repo page's Audits table gains a Findings column
     ("12 · 1 Critical, 4 High") and marks the latest audit.
  3. A finding card's location sits under its title, readable, and links to
     the line on GitHub at the audited commit when that commit is stored.
  4. Finding titles are sentence case at render time, acronyms kept.
  5. The audit-mode note is one line.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from codeguard.api import access
from codeguard.api import audits as audits_mod
from codeguard.api.display import blob_url, finding_counts, sentence_case
from tests.api.conftest import insert_review

OWNER = "ashrithaumd"
REPO = "codeguard-playground"
VIEWER = "ashrithaumd"
OTHER = "someone-else"
SHA = "4e02d10" + "a" * 33


def _report(counts=None, findings=None):
    counts = counts or {"critical": 1, "high": 4, "medium": 5, "low": 2}
    findings = findings if findings is not None else [
        {"severity": "high", "title": "SQL Injection via String Formatting", "file": "db.py",
         "start_line": 13, "end_line": 13, "source_line": 0, "flow": "", "what": "w", "why": "", "fix": "",
         "message": "m", "rules": ["B608"], "source_tool": "security", "unreviewed": False},
        {"severity": "low", "title": "Full response logged", "file": "app/log util.py",
         "start_line": 81, "end_line": 83, "source_line": 0, "flow": "", "what": "w", "why": "", "fix": "",
         "message": "m", "rules": ["x"], "source_tool": "ai_aware", "unreviewed": False},
    ]
    return {"version": 1, "target": f"https://github.com/{OWNER}/{REPO}",
            "summary": {"files_scanned": 3, "files_ai_aware": 1, "total": sum(counts.values()),
                        "counts": counts, "repo_level": 0, "dismissed": 0, "skipped_test_asserts": 0,
                        "unreviewed": 0, "verdict_calls_failed": 0},
            "incomplete": [], "findings": findings, "repo_level": [], "dismissed": [],
            "skipped_files": [], "verdict_call_failures": [],
            "technical": {"tokens_in": 100, "tokens_out": 10, "estimated_cost_usd": 0.03,
                          "elapsed_s": 5.0, "models": {}}}


async def _audit(pool, *, requested_by=VIEWER, report_json=None, markdown="# r\n", cost=0.0,
                 tokens_in=0, created_at=None, commit_sha=None, status="done"):
    audit_id = uuid.uuid4()
    created_at = created_at or datetime.now(timezone.utc)
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO audits (id, owner, repo, requested_by, private, status, created_at) "
            "VALUES (%s, %s, %s, %s, FALSE, 'running', %s)",
            (audit_id, OWNER, REPO, requested_by, created_at),
        )
    await audits_mod.finish_audit(
        pool, audit_id, status=status, report_markdown=markdown, report_json=report_json,
        exit_code=0, tokens_in=tokens_in, estimated_cost_usd=cost, duration_s=4.0, commit_sha=commit_sha,
    )
    return audit_id


def _repo_page(client):
    with patch.object(access, "_is_collaborator", return_value=True):
        return client.get(f"/dashboard/repos/{OWNER}/{REPO}").text


def _stats(html):
    return html.split('class="stats"')[1].split("</div>\n</div>")[0]


# --------------------------------------------------------------------------
# 1. Tiles
# --------------------------------------------------------------------------

async def test_every_tile_includes_the_viewers_audits_with_a_breakdown(client, pool, as_principal):
    await insert_review(pool, owner=OWNER, repo=REPO, private=False, findings_total=2, det=2,
                        estimated_cost_usd=0.01)
    await _audit(pool, report_json=_report(), cost=0.0347, tokens_in=6701)
    await _audit(pool, requested_by=OTHER, report_json=_report(), cost=0.5, tokens_in=99999)
    as_principal(VIEWER)
    stats = _stats(_repo_page(client))

    assert re.search(r'class="k">Activity</div><div class="v">2<', stats)
    assert re.search(r'class="k">(?:(?!class="v").)*?Findings.*?class="v">14<', stats, re.S)  # 2 + 12
    assert "6,701" in stats                                                       # tokens: 0 + 6701
    assert "$0.0447" in stats
    assert stats.count("1 review · 1 audit") >= 1
    assert "99,999" not in stats and "$0.5" not in stats


# --------------------------------------------------------------------------
# 2. Audits table: findings column, latest marked
# --------------------------------------------------------------------------

async def test_the_audits_table_shows_findings_and_marks_the_latest(client, pool, as_principal):
    old = await _audit(pool, report_json=_report({"critical": 0, "high": 0, "medium": 3, "low": 1}),
                       created_at=datetime.now(timezone.utc) - timedelta(days=1))
    new = await _audit(pool, report_json=_report())
    as_principal(VIEWER)
    html = _repo_page(client)
    table = html[html.index("<h2>Audits</h2>"):]

    rows = re.findall(r'<tr class="row-link" data-href="/dashboard/audits/([^"]+)">(.*?)</tr>', table, re.S)
    assert [r[0] for r in rows] == [str(new), str(old)]
    assert "12 · 1 Critical, 4 High" in rows[0][1]
    assert "4 · 3 Medium" in rows[1][1]
    assert ">Latest<" in rows[0][1] and ">Latest<" not in rows[1][1]


async def test_an_audit_from_before_report_json_takes_its_counts_from_the_markdown(client, pool, as_principal):
    legacy = ("# CodeGuard audit: x\n\n13 finding(s) across 3 scanned file(s) (...).\n\n"
              "## Findings by severity\n\n### High (5)\n\n- a\n\n### Medium (6)\n\n- b\n\n### Low (2)\n\n- c\n")
    await _audit(pool, markdown=legacy)
    as_principal(VIEWER)
    table = _repo_page(client).split("<h2>Audits</h2>")[1]
    assert "13 · 5 High" in table


def test_finding_counts_formatting():
    assert finding_counts({"report_json": _report(), "report_markdown": ""})["label"] == "12 · 1 Critical, 4 High"
    assert finding_counts({"report_json": _report({"critical": 0, "high": 0, "medium": 0, "low": 0}),
                           "report_markdown": ""})["label"] == "0"
    assert finding_counts({"report_json": None, "report_markdown": None}) is None


# --------------------------------------------------------------------------
# 3. Location under the title, linked to the audited commit
# --------------------------------------------------------------------------

async def _audit_page(client, pool, as_principal, **kw):
    audit_id = await _audit(pool, report_json=_report(), **kw)
    as_principal(VIEWER)
    return client.get(f"/dashboard/audits/{audit_id}").text


async def test_the_location_sits_under_the_title_and_links_to_the_line(client, pool, as_principal):
    html = await _audit_page(client, pool, as_principal, commit_sha=SHA)

    assert re.search(
        rf'<a class="finding-loc" href="https://github.com/{OWNER}/{REPO}/blob/{SHA}/db.py#L13" '
        r'target="_blank" rel="noopener noreferrer">db.py:13</a>', html)
    # A range, and a path that needs encoding.
    assert f'href="https://github.com/{OWNER}/{REPO}/blob/{SHA}/app/log%20util.py#L81-L83"' in html


async def test_the_location_is_inside_the_title_block_not_the_header_row(client, pool, as_principal):
    html = await _audit_page(client, pool, as_principal, commit_sha=SHA)
    title_block = re.search(r'<div class="finding-titles">(.*?)</div>', html, re.S).group(1)
    assert "finding-title" in title_block and "finding-loc" in title_block


async def test_without_a_stored_commit_the_location_is_plain_text(client, pool, as_principal):
    html = await _audit_page(client, pool, as_principal, commit_sha=None)
    assert re.search(r'<code class="finding-loc">db.py:13</code>', html)
    assert "/blob/" not in html


@pytest.mark.parametrize("sha", ["not-a-sha", "../../evil", "A" * 40])
def test_blob_url_refuses_anything_but_a_full_lowercase_sha(sha):
    assert blob_url(OWNER, REPO, sha, "db.py", 13, 13) is None


def test_blob_url_refuses_a_path_that_climbs():
    assert blob_url(OWNER, REPO, SHA, "../../etc/passwd", 1, 1) is None


async def test_the_audit_records_its_commit(pool):
    audit_id = await _audit(pool, commit_sha=SHA)
    assert (await audits_mod.get_audit(pool, audit_id))["commit_sha"] == SHA


# --------------------------------------------------------------------------
# 4. Sentence case
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("SQL Injection via String Formatting", "SQL injection via string formatting"),
    ("Full response logged", "Full response logged"),
    ("No Timeout On The LLM Call", "No timeout on the LLM call"),
    ("Model Output Flows Into eval()", "Model output flows into eval()"),
    ("Missing max_tokens Cap On OpenAI Call", "Missing max_tokens cap on OpenAI call"),
    ("Hardcoded API Key In Anthropic Client", "Hardcoded API key in Anthropic client"),
    ("unpinned model alias", "Unpinned model alias"),
    ("", ""),
])
def test_sentence_case(raw, expected):
    assert sentence_case(raw) == expected


async def test_titles_render_in_sentence_case(client, pool, as_principal):
    html = await _audit_page(client, pool, as_principal)
    assert ">SQL injection via string formatting<" in html
    assert "SQL Injection via String Formatting" not in html


# --------------------------------------------------------------------------
# 5. The audit-mode note
# --------------------------------------------------------------------------

async def test_the_audit_note_is_one_line(client, pool, as_principal):
    html = await _audit_page(client, pool, as_principal)
    assert '<p class="note">Audit mode: findings and how to fix them; no code patches (audits have no diff).</p>' in html


# --------------------------------------------------------------------------
# Tiles, second pass: findings are not summed across audits
# --------------------------------------------------------------------------

async def test_findings_count_the_latest_audit_only_not_every_audit(client, pool, as_principal):
    """Re-auditing a repository finds mostly the same issues; 13 + 12 = 25
    overstated it. Findings = reviews + the latest audit. Cost and tokens
    still sum every run, because every run was paid for."""
    await insert_review(pool, owner=OWNER, repo=REPO, private=False, findings_total=2, det=2,
                        estimated_cost_usd=0.01)
    await _audit(pool, report_json=_report({"critical": 0, "high": 5, "medium": 6, "low": 2}),
                 cost=0.0347, tokens_in=5756, created_at=datetime.now(timezone.utc) - timedelta(days=1))
    await _audit(pool, report_json=_report(), cost=0.0544, tokens_in=6701)
    as_principal(VIEWER)
    stats = _stats(_repo_page(client))

    assert re.search(r'class="k">(?:(?!class="v").)*?Findings.*?class="v">14<', stats, re.S)  # 2 + 12, not 2 + 25
    assert "2 in reviews · 12 in latest audit" in stats
    assert "12,457" in stats                                   # tokens: every run
    assert "$0.0991" in stats                                  # cost: every run (0.01 + 0.0347 + 0.0544)


async def test_a_failed_latest_audit_falls_back_to_the_latest_with_counts(client, pool, as_principal):
    await _audit(pool, report_json=_report(), created_at=datetime.now(timezone.utc) - timedelta(hours=2))
    await _audit(pool, status="failed", markdown=None)
    as_principal(VIEWER)
    assert "0 in reviews · 12 in latest audit" in _stats(_repo_page(client))


async def test_the_cost_split_shows_amounts(client, pool, as_principal):
    await _audit(pool, report_json=_report(), cost=0.0544)
    await _audit(pool, report_json=_report(), cost=0.0348,
                 created_at=datetime.now(timezone.utc) - timedelta(days=1))
    as_principal(VIEWER)
    stats = _stats(_repo_page(client))
    assert "$0.0000 reviews · $0.0892 audits" in stats
