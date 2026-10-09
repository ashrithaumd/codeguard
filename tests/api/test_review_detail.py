"""Review detail: layout, dismissals and the files that were not reviewed.

  * #6 the message column was squeezed by a "Suggested fix" column that
    was empty for most rows. The column is gone; a finding WITH a fix gets
    an expandable row under it.
  * #7 Composition said 9 dismissed and none were listed in view. They are
    now a collapsed "Dismissed by AI (N)" section whenever N > 0.
  * #8 the banner said 48 files were skipped and the list showed 5. The
    list now says how many it shows of how many, grouped by reason, each
    path once.
"""

from __future__ import annotations

import re
from unittest.mock import patch

from codeguard.api import access
from tests.api.conftest import insert_review

OWNER = "ashrithaumd"
REPO = "codeguard-playground"


def _finding(fp, line, message="A message about this line.", rule="B608"):
    return {"file": "db.py", "start_line": line, "end_line": line, "severity": "HIGH",
            "source_tool": "security", "rule_id": rule, "message": message,
            "fingerprint": fp, "confidence": 1.0}


def _get(client, job_id):
    with patch.object(access, "_is_collaborator", return_value=True):
        return client.get(f"/dashboard/reviews/{job_id}").text


async def test_no_empty_suggested_fix_column(client, pool, as_principal):
    job = await insert_review(pool, owner=OWNER, repo=REPO, findings_total=1, vc=1,
                              findings=[_finding("aaaa", 13)])
    as_principal(OWNER)
    html = _get(client, job)

    assert "No suggestion" not in html
    assert not re.search(r"<th[^>]*>.*Suggested fix.*</th>", html)


async def test_a_fix_is_an_expandable_row_under_its_finding(client, pool, as_principal):
    fix = {"fingerprint": "bbbb", "suggestion_body": "```suggestion\nx = 1\n```",
           "target_file": "db.py", "target_line": 20, "target_end_line": 20, "original_text": "x = 0"}
    job = await insert_review(pool, owner=OWNER, repo=REPO, findings_total=2, vc=2,
                              findings=[_finding("aaaa", 13), _finding("bbbb", 20)], fixes=[fix])
    as_principal(OWNER)
    html = _get(client, job)

    assert html.count("<summary") >= 1
    assert re.search(r'<tr class="fix-row">.*?<details.*?<summary[^>]*>\s*Suggested fix', html, re.S)
    assert html.count('class="fix-row"') == 1


async def test_dismissed_findings_are_a_collapsed_section(client, pool, as_principal):
    dismissed = [{"file": "db.py", "start_line": n, "rule_id": "B101", "reason": f"reason {n}"}
                 for n in range(1, 10)]
    job = await insert_review(pool, owner=OWNER, repo=REPO, dismissed_count=9, dismissed=dismissed)
    as_principal(OWNER)
    html = _get(client, job)

    assert re.search(r"<details[^>]*>\s*<summary[^>]*>\s*Dismissed by AI \(9\)", html)
    for n in range(1, 10):
        assert f"reason {n}" in html


async def test_no_dismissed_section_when_there_are_none(client, pool, as_principal):
    job = await insert_review(pool, owner=OWNER, repo=REPO, dismissed_count=0)
    as_principal(OWNER)
    assert "Dismissed by AI" not in _get(client, job)


async def test_files_not_reviewed_says_how_many_it_shows_of_how_many(client, pool, as_principal):
    filtered = [
        {"path": "a.py", "reason": "dropped by max_files budget"},
        {"path": "b.py", "reason": "dropped by max_files budget"},
        {"path": "c.py", "reason": "dropped by max_tokens budget"},
        {"path": "c.py", "reason": "dropped by max_tokens budget"},   # two hunks, one file
        {"path": "poetry.lock", "reason": "lockfile"},
    ]
    job = await insert_review(pool, owner=OWNER, repo=REPO, files_seen=63, files_reviewed=15,
                              budget_exceeded=True, filtered=filtered)
    as_principal(OWNER)
    html = _get(client, job)

    assert "4 shown of 48" in html
    assert html.count(">c.py<") == 1
    groups = re.findall(r'class="reason-group">\s*<h3>([^<]+)</h3>', html)
    assert [g.strip() for g in groups] == [
        "dropped by max_files budget (2)", "dropped by max_tokens budget (1)", "lockfile (1)",
    ]


async def test_when_every_skipped_file_is_listed_it_just_says_the_count(client, pool, as_principal):
    filtered = [{"path": "a.py", "reason": "lockfile"}]
    job = await insert_review(pool, owner=OWNER, repo=REPO, files_seen=4, files_reviewed=3, filtered=filtered)
    as_principal(OWNER)
    html = _get(client, job)
    assert "shown of" not in html
    assert "Files not reviewed" in html


async def test_unreviewed_findings_are_announced_on_review_detail(client, pool, as_principal):
    unreviewed = {**_finding("cccc", 13), "source_tool": "bandit", "unreviewed": True}
    job = await insert_review(pool, owner=OWNER, repo=REPO, findings_total=2, vc=1, unv=1,
                              findings=[unreviewed, _finding("dddd", 20)])
    as_principal(OWNER)
    html = _get(client, job)

    assert "AI review unavailable for 1 finding(s); shown unreviewed." in html
    assert html.count(">Unreviewed<") == 1


async def test_no_unreviewed_notice_when_every_finding_was_reviewed(client, pool, as_principal):
    job = await insert_review(pool, owner=OWNER, repo=REPO, findings_total=1, vc=1,
                              findings=[_finding("eeee", 13)])
    as_principal(OWNER)
    assert "AI review unavailable" not in _get(client, job)
