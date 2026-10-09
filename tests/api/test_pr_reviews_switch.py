"""The per-repo "PR reviews" switch.

ON: a pull_request delivery is queued for review as before. OFF: the
delivery is acknowledged and nothing is queued, so there is no LLM call,
no check run and no comment. Unknown repos are OFF.

The switch is operator-only. Anyone else gets 404 from the POST, the same
as every other operator route here, and never sees the switch rendered.
The migration seeds ON only for repositories with REAL reviews: rows
written by scripts/seed_demo.py are labelled and excluded, so a local
database full of sample data seeds nothing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from unittest.mock import patch

import pytest

from codeguard.api import access, csrf
from codeguard.api import repo_settings
from codeguard.config import Settings, get_settings
from codeguard.queue.db import bootstrap_schema
from tests.api.conftest import insert_review

OWNER = "ashrithaumd"
REPO = "reliqueue"
OPERATOR = "ashrithaumd"
VISITOR = "someone-else"
SECRET = "switch-test-secret"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

@pytest.fixture
def signed_webhooks(monkeypatch):
    base = get_settings().model_dump()
    base["github_webhook_secret"] = SECRET
    monkeypatch.setattr("codeguard.api.routes.webhooks.get_settings", lambda: Settings(**base))


def _pr_payload(owner=OWNER, repo=REPO, action="opened", number=12):
    return {
        "action": action, "number": number,
        "installation": {"id": 4934663},
        "repository": {"name": repo, "owner": {"login": owner}, "private": False},
        "pull_request": {"title": "t", "head": {"sha": "b" * 40}, "base": {"ref": "main"},
                         "draft": False, "labels": []},
    }


def _deliver(client, payload, event="pull_request", delivery="d-1"):
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return client.post("/webhook", content=body, headers={
        "X-GitHub-Event": event, "X-GitHub-Delivery": delivery,
        "X-Hub-Signature-256": sig, "Content-Type": "application/json",
    })


async def _jobs(pool) -> int:
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM jobs WHERE type = 'pull_request_review'")
        return (await cur.fetchone())["count"]


async def _setting(pool, owner=OWNER, repo=REPO):
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT pr_reviews_enabled, updated_by FROM repo_settings "
            "WHERE lower(owner) = lower(%s) AND lower(repo) = lower(%s)", (owner, repo))
        return await cur.fetchone()


def _installed(*repos):
    return [{"owner": OWNER, "repo": r, "private": False, "installation_id": 4934663,
             "html_url": f"https://github.com/{OWNER}/{r}"} for r in repos]


def _switch(client, enabled: bool, owner=OWNER, repo=REPO, token=None, collaborator=True):
    with patch.object(access, "_is_collaborator", return_value=collaborator):
        access.reset_caches()
        client.get("/dashboard")
        return client.post(
            f"/dashboard/repos/{owner}/{repo}/pr-reviews",
            data={"enabled": "on" if enabled else "off",
                  "csrf_token": client.cookies.get(csrf.COOKIE_NAME, "") if token is None else token},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )


# --------------------------------------------------------------------------
# The webhook
# --------------------------------------------------------------------------

async def test_a_repo_with_the_switch_off_is_acknowledged_and_not_queued(client, pool, signed_webhooks):
    resp = _deliver(client, _pr_payload())
    assert resp.status_code == 200
    assert resp.json() == {"status": "skipped", "reason": "pr_reviews_off"}
    assert await _jobs(pool) == 0


async def test_a_repo_with_the_switch_on_is_queued(client, pool, signed_webhooks):
    await repo_settings.set_pr_reviews(pool, OWNER, REPO, enabled=True, updated_by=OPERATOR)
    resp = _deliver(client, _pr_payload())
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
    assert await _jobs(pool) == 1


async def test_the_switch_matches_owner_and_repo_case_insensitively(client, pool, signed_webhooks):
    await repo_settings.set_pr_reviews(pool, "AshrithaUMD", "RelIQueue", enabled=True, updated_by=OPERATOR)
    _deliver(client, _pr_payload(owner="ashrithaumd", repo="reliqueue"))
    assert await _jobs(pool) == 1


async def test_turning_it_off_again_stops_the_next_delivery(client, pool, signed_webhooks):
    await repo_settings.set_pr_reviews(pool, OWNER, REPO, enabled=True, updated_by=OPERATOR)
    await repo_settings.set_pr_reviews(pool, OWNER, REPO, enabled=False, updated_by=OPERATOR)
    assert _deliver(client, _pr_payload()).json()["status"] == "skipped"
    assert await _jobs(pool) == 0


async def test_a_bad_signature_is_still_refused_before_the_switch_is_read(client, pool, signed_webhooks):
    body = json.dumps(_pr_payload()).encode()
    resp = client.post("/webhook", content=body, headers={
        "X-GitHub-Event": "pull_request", "X-Hub-Signature-256": "sha256=" + "0" * 64})
    assert resp.status_code == 401


# --------------------------------------------------------------------------
# The switch route
# --------------------------------------------------------------------------

async def test_the_operator_can_turn_it_on_and_off(client, pool, as_principal):
    as_principal(OPERATOR, audit_principals=OPERATOR)

    resp = _switch(client, True)
    assert resp.status_code == 303 and resp.headers["location"] == "/dashboard/repos"
    assert dict(await _setting(pool)) == {"pr_reviews_enabled": True, "updated_by": OPERATOR}

    _switch(client, False)
    assert (await _setting(pool))["pr_reviews_enabled"] is False


async def test_a_signed_in_non_operator_gets_404_and_nothing_changes(client, pool, as_principal):
    as_principal(VISITOR, audit_principals=OPERATOR)
    assert _switch(client, True).status_code == 404
    assert await _setting(pool) is None


async def test_an_anonymous_visitor_gets_404(anon_client, pool):
    anon_client.get("/dashboard")
    resp = anon_client.post(f"/dashboard/repos/{OWNER}/{REPO}/pr-reviews", data={"enabled": "on"},
                            headers={"Origin": "http://testserver"}, follow_redirects=False)
    assert resp.status_code == 404
    assert await _setting(pool) is None


async def test_the_operator_without_a_csrf_token_gets_403(client, pool, as_principal):
    as_principal(OPERATOR, audit_principals=OPERATOR)
    assert _switch(client, True, token="").status_code == 403
    assert await _setting(pool) is None


async def test_the_operator_without_access_to_the_repo_gets_404(client, pool, as_principal):
    as_principal(OPERATOR, audit_principals=OPERATOR)
    assert _switch(client, True, collaborator=False).status_code == 404
    assert await _setting(pool) is None


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------

def _repos_page(client):
    with patch.object(access, "installed_repositories", return_value=_installed(REPO, "DocuMind")), \
         patch.object(access, "_is_collaborator", return_value=True):
        return client.get("/dashboard/repos").text


async def test_the_operator_sees_a_switch_per_row_with_its_state(client, pool, as_principal):
    await repo_settings.set_pr_reviews(pool, OWNER, REPO, enabled=True, updated_by=OPERATOR)
    as_principal(OPERATOR, audit_principals=OPERATOR)
    html = _repos_page(client)

    assert html.count('class="pr-reviews-switch"') == 2
    on_form = html[html.index(f'action="/dashboard/repos/{OWNER}/{REPO}/pr-reviews"'):]
    on_form = on_form[:on_form.index("</form>")]
    assert 'value="off"' in on_form and 'aria-pressed="true"' in on_form
    off_form = html[html.index(f'action="/dashboard/repos/{OWNER}/DocuMind/pr-reviews"'):]
    off_form = off_form[:off_form.index("</form>")]
    assert 'value="on"' in off_form and 'aria-pressed="false"' in off_form


async def test_a_non_operator_sees_no_switch(client, pool, as_principal):
    await repo_settings.set_pr_reviews(pool, OWNER, REPO, enabled=True, updated_by=OPERATOR)
    as_principal(VISITOR, audit_principals=OPERATOR)
    html = _repos_page(client)
    assert f"{OWNER}/{REPO}" in html  # the row is there, so the absence below is not vacuous
    assert "pr-reviews-switch" not in html and "/pr-reviews" not in html


# --------------------------------------------------------------------------
# The migration's seed
# --------------------------------------------------------------------------

async def test_the_migration_seeds_on_only_for_repos_with_real_reviews(client, pool):
    await insert_review(pool, owner=OWNER, repo="real-one", pr_title="Fix the thing")
    await insert_review(pool, owner=OWNER, repo="sample-by-title", pr_title="[SAMPLE] Add a feature",
                        pr_number=9001)
    await insert_review(pool, owner=OWNER, repo="sample-by-body", pr_title="Looks real",
                        summary_body="SAMPLE DATA - not a real review. Seeded locally.", pr_number=9002)
    await insert_review(pool, owner="codeguard-fixtures", repo="legacy", pr_title="old fixture")

    await bootstrap_schema(pool)

    async with pool.connection() as conn:
        cur = await conn.execute("SELECT owner, repo, pr_reviews_enabled FROM repo_settings ORDER BY repo")
        rows = await cur.fetchall()
    assert [dict(r) for r in rows] == [{"owner": OWNER, "repo": "real-one", "pr_reviews_enabled": True}]


async def test_the_seed_is_idempotent_and_never_turns_a_switch_back_on(client, pool):
    await insert_review(pool, owner=OWNER, repo="real-one", pr_title="Fix the thing")
    await bootstrap_schema(pool)
    await repo_settings.set_pr_reviews(pool, OWNER, "real-one", enabled=False, updated_by=OPERATOR)

    await bootstrap_schema(pool)  # every api/worker startup re-runs every migration

    assert (await _setting(pool, repo="real-one"))["pr_reviews_enabled"] is False
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT count(*) FROM repo_settings")
        assert (await cur.fetchone())["count"] == 1
