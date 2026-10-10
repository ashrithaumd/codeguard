"""Audits: files no scanner covers, inside the existing "Skipped" section.

No new section, card or panel: the list is items in the Skipped fold the
page already has, and the fold's heading counts them ("Skipped (83 test
asserts, 3 files not covered)"). An audit without uncovered files -- every
audit stored before this -- renders exactly as before.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from codeguard.api import audits as audits_mod

OWNER = VIEWER = "ashrithaumd"


def _report(not_covered=None, skipped_test_asserts=0):
    r = {"version": 1, "target": f"https://github.com/{OWNER}/r",
         "summary": {"files_scanned": 3, "files_ai_aware": 0, "total": 0,
                     "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "repo_level": 0,
                     "dismissed": 0, "skipped_test_asserts": skipped_test_asserts, "unreviewed": 0,
                     "verdict_calls_failed": 0},
         "incomplete": [], "findings": [], "repo_level": [], "dismissed": [], "skipped_files": [],
         "verdict_call_failures": [],
         "technical": {"tokens_in": 1, "tokens_out": 1, "estimated_cost_usd": 0.0, "elapsed_s": 1.0, "models": {}}}
    if not_covered is not None:
        r["not_covered"] = not_covered
    return r


async def _page(client, pool, as_principal, report):
    audit_id = uuid.uuid4()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO audits (id, owner, repo, requested_by, private, status, created_at) "
            "VALUES (%s, %s, 'r', %s, FALSE, 'running', %s)",
            (audit_id, OWNER, VIEWER, datetime.now(timezone.utc)))
    await audits_mod.finish_audit(pool, audit_id, status="done", report_markdown="# r\n", report_json=report)
    as_principal(VIEWER)
    return client.get(f"/dashboard/audits/{audit_id}").text


GAPS = [{"language": "Go", "paths": ["cmd/main.go", "pkg/util.go"]},
        {"language": "Ruby", "paths": ["app/user.rb"]}]


def _skipped_fold(html):
    m = re.search(r'<details class="panel fold">\s*<summary class="panel-head">Skipped.*?</details>', html, re.S)
    return m.group(0) if m else ""


async def test_uncovered_files_are_listed_inside_the_skipped_section(client, pool, as_principal):
    html = await _page(client, pool, as_principal, _report(GAPS, skipped_test_asserts=83))
    fold = _skipped_fold(html)
    assert re.search(r"Skipped \(83 test asserts, 3 files not covered\)", fold)
    assert "Not covered by any scanner" in fold
    assert "Go (2)" in fold and "cmd/main.go" in fold and "pkg/util.go" in fold
    assert "Ruby (1)" in fold and "app/user.rb" in fold
    # Every mention is inside that section: one item per language.
    assert html.count("Not covered by any scanner") == fold.count("Not covered by any scanner") == 2


async def test_the_section_appears_for_uncovered_files_alone(client, pool, as_principal):
    fold = _skipped_fold(await _page(client, pool, as_principal, _report(GAPS)))
    assert re.search(r"Skipped \(3 files not covered\)", fold)


async def test_no_new_sections_or_panels(client, pool, as_principal):
    with_gaps = await _page(client, pool, as_principal, _report(GAPS, skipped_test_asserts=1))
    without = await _page(client, pool, as_principal, _report([], skipped_test_asserts=1))
    for tag in ("<details", "<section", 'class="panel'):
        assert with_gaps.count(tag) == without.count(tag), tag


async def test_an_older_audit_renders_exactly_as_before(client, pool, as_principal):
    html = await _page(client, pool, as_principal, _report(None, skipped_test_asserts=83))
    assert "Not covered by any scanner" not in html
    assert re.search(r"Skipped \(83 test asserts\)", _skipped_fold(html))


async def test_a_long_list_is_capped_with_a_count(client, pool, as_principal):
    many = [{"language": "Go", "paths": [f"pkg/f{i}.go" for i in range(25)]}]
    fold = _skipped_fold(await _page(client, pool, as_principal, _report(many)))
    assert "Go (25)" in fold and "pkg/f9.go" in fold and "pkg/f10.go" not in fold and "+15 more" in fold
