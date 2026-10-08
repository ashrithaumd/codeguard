"""The Repositories page's activity columns: reviews AND audits.

Two things are pinned here.

  * A finished audit shows "last: done" on its own row. Reported on
    localhost as missing after a refresh; the server rendered it correctly
    on re-request, so the fix was Cache-Control (test_security_headers.py)
    and this is the regression test for the row itself.

  * Activity, Last activity and Total cost combine reviews with audits --
    but only the VIEWER'S OWN audits. An audit is visible only to the
    person who requested it (_may_read_audit), so folding everybody's
    audit spend into a shared total would disclose that somebody else
    audited the repository, when, and what it cost them.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from codeguard.api import access
from tests.api.conftest import insert_review

OWNER = "ashrithaumd"
PUBLIC = "codeguard-playground"
VIEWER = "ashrithaumd"
OTHER = "someone-else"


def _installed(*repos):
    return [
        {"owner": OWNER, "repo": r, "private": False,
         "installation_id": 4934663, "html_url": f"https://github.com/{OWNER}/{r}"}
        for r in repos
    ]


async def _insert_audit(pool, *, repo=PUBLIC, requested_by=VIEWER, status="done",
                        cost=0.0, created_at=None):
    audit_id = uuid.uuid4()
    created_at = created_at or datetime.now(timezone.utc)
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO audits (id, owner, repo, requested_by, private, status, "
            "estimated_cost_usd, report_markdown, created_at, finished_at) "
            "VALUES (%s, %s, %s, %s, FALSE, %s, %s, '# r', %s, %s)",
            (audit_id, OWNER, repo, requested_by, status, cost, created_at, created_at),
        )
    return audit_id


def _row(html: str, repo: str) -> str:
    """The <tr> for one repository, so an assertion cannot be satisfied
    by some other row on the page."""
    for tr in re.findall(r"<tr class=\"row-link\".*?</tr>", html, re.S):
        if f"/dashboard/repos/{OWNER}/{repo}\"" in tr:
            return tr
    raise AssertionError(f"no row for {repo}")


def _get(client, *repos):
    with patch.object(access, "installed_repositories", return_value=_installed(*repos)), \
         patch.object(access, "_is_collaborator", return_value=True):
        return client.get("/dashboard/repos")


async def test_a_finished_audit_shows_last_done_on_its_own_row(client, pool, as_principal):
    audit_id = await _insert_audit(pool)
    as_principal(VIEWER, audit_principals=VIEWER)

    resp = _get(client, PUBLIC, "reliqueue")

    row = _row(resp.text, PUBLIC)
    assert f"/dashboard/audits/{audit_id}" in row
    assert re.search(r"last:\s*done", row)
    assert "last:" not in _row(resp.text, "reliqueue")


async def test_activity_combines_reviews_and_the_viewers_audits(client, pool, as_principal):
    await insert_review(pool, owner=OWNER, repo=PUBLIC, private=False, estimated_cost_usd=0.01)
    await _insert_audit(pool, cost=0.02)
    as_principal(VIEWER, audit_principals=VIEWER)

    resp = _get(client, PUBLIC)

    assert ">Activity<" in resp.text
    assert "Last activity" in resp.text
    row = _row(resp.text, PUBLIC)
    assert "1 review" in row and "1 audit" in row
    assert "$0.0300" in row


async def test_an_audit_alone_is_activity(client, pool, as_principal):
    """The reported symptom: after an audit the row still said Never / 0."""
    await _insert_audit(pool, cost=0.0347)
    as_principal(VIEWER, audit_principals=VIEWER)

    row = _row(_get(client, PUBLIC).text, PUBLIC)

    assert "Never" not in row
    assert "1 audit" in row
    assert "$0.0347" in row


async def test_another_viewers_audit_is_not_counted_or_costed(client, pool, as_principal):
    """Two viewers, both able to see the repository. Each sees only their
    own audit activity; the reviews, which are not per-requester, both see."""
    await insert_review(pool, owner=OWNER, repo=PUBLIC, private=False, estimated_cost_usd=0.01)
    earlier = datetime.now(timezone.utc) - timedelta(days=2)
    await _insert_audit(pool, requested_by=OTHER, cost=0.5)
    await _insert_audit(pool, requested_by=VIEWER, cost=0.02, created_at=earlier)

    as_principal(VIEWER, audit_principals=VIEWER)
    mine = _row(_get(client, PUBLIC).text, PUBLIC)
    assert "$0.0300" in mine
    assert "$0.5" not in mine
    assert "1 audit" in mine

    as_principal(OTHER)
    theirs = _row(_get(client, PUBLIC).text, PUBLIC)
    assert "$0.5100" in theirs
    assert "$0.0300" not in theirs
    assert "1 audit" in theirs


async def test_the_audit_note_is_a_tooltip_on_the_button_not_a_banner(client, pool, as_principal, monkeypatch):
    """It was a banner that said the same thing twice ("Audit mode reports
    findings only. Audit mode reports findings only -- ..."). Now: once,
    on the button it describes, and no banner at all."""
    monkeypatch.setattr("codeguard.api.repo_url.verify_public_and_sized",
                        lambda owner, repo: {"private": False, "size": 100})
    as_principal(VIEWER, audit_principals=VIEWER)
    html = _get(client, PUBLIC).text

    assert html.lower().count("audit mode: findings and how to fix them") == 1
    assert '<div class="banner" role="note">' not in html
    row = _row(html, PUBLIC)
    assert re.search(r'data-tip="Audit mode: findings and how to fix them[^"]*"[^>]*>\s*<form', row) or \
        re.search(r'data-tip="Audit mode: findings and how to fix them', row)
