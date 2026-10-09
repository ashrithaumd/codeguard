"""New-repository notices on the Repositories page.

With the App installed on "All repositories", GitHub sends
installation_repositories (added) when a repository is created, forked
into the account, or transferred in. Each added repository becomes a
dismissible notice: "New repository: <name> -- Run audit / Turn on PR
reviews / Dismiss". A plain `git clone` creates nothing on GitHub and
sends nothing, so it cannot appear here.

Operators only: the installation list is a fact about the operator, so
nobody else sees a notice or may dismiss one (404).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from unittest.mock import patch

import pytest

from codeguard.api import access, csrf, repo_notices
from codeguard.config import Settings, get_settings

OWNER = "ashrithaumd"
OPERATOR = "ashrithaumd"
VISITOR = "someone-else"
SECRET = "notices-secret"


@pytest.fixture
def signed_webhooks(monkeypatch):
    base = get_settings().model_dump()
    base["github_webhook_secret"] = SECRET
    monkeypatch.setattr("codeguard.api.routes.webhooks.get_settings", lambda: Settings(**base))


def _repo(name, private=False):
    return {"id": abs(hash(name)) % 10**9, "name": name, "full_name": f"{OWNER}/{name}", "private": private}


def _deliver(client, event, payload, secret=SECRET):
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return client.post("/webhook", content=body, headers={
        "X-GitHub-Event": event, "X-GitHub-Delivery": uuid.uuid4().hex,
        "X-Hub-Signature-256": sig, "Content-Type": "application/json",
    })


def _added(*repos):
    return {"action": "added", "installation": {"id": 4934663}, "repository_selection": "all",
            "repositories_added": list(repos), "repositories_removed": []}


def _removed(*repos):
    return {"action": "removed", "installation": {"id": 4934663}, "repository_selection": "all",
            "repositories_added": [], "repositories_removed": list(repos)}


async def _notices(pool):
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT owner, repo, private, dismissed_at IS NOT NULL AS dismissed, dismissed_by "
            "FROM repo_notices ORDER BY repo")
        return [dict(r) for r in await cur.fetchall()]


def _installed(*names):
    return [{"owner": OWNER, "repo": n, "private": False, "installation_id": 4934663,
             "html_url": f"https://github.com/{OWNER}/{n}"} for n in names]


def _page(client, *installed, collaborator=True):
    with patch.object(access, "installed_repositories", return_value=_installed(*installed)), \
         patch.object(access, "_is_collaborator", return_value=collaborator):
        access.reset_caches()
        return client.get("/dashboard/repos").text


def _notice_block(html):
    start = html.index('class="repo-notices"')
    return html[start:html.index("</section>", start)]


def _post(client, path, token=None):
    with patch.object(access, "_is_collaborator", return_value=True):
        client.get("/dashboard")
        return client.post(path, data={"csrf_token": client.cookies.get(csrf.COOKIE_NAME, "") if token is None else token},
                           headers={"Origin": "http://testserver"}, follow_redirects=False)


# --------------------------------------------------------------------------
# The events
# --------------------------------------------------------------------------

async def test_added_repositories_become_notices(client, pool, signed_webhooks):
    resp = _deliver(client, "installation_repositories", _added(_repo("fresh"), _repo("forked", private=True)))
    assert resp.status_code == 200 and resp.json() == {"status": "ok"}
    assert await _notices(pool) == [
        {"owner": OWNER, "repo": "forked", "private": True, "dismissed": False, "dismissed_by": None},
        {"owner": OWNER, "repo": "fresh", "private": False, "dismissed": False, "dismissed_by": None},
    ]


async def test_a_redelivery_does_not_duplicate_or_revive_a_notice(client, pool, signed_webhooks):
    _deliver(client, "installation_repositories", _added(_repo("fresh")))
    await repo_notices.dismiss(pool, OWNER, "fresh", dismissed_by=OPERATOR)
    _deliver(client, "installation_repositories", _added(_repo("fresh")))
    assert [(n["repo"], n["dismissed"]) for n in await _notices(pool)] == [("fresh", True)]


async def test_a_removed_repository_loses_its_notice(client, pool, signed_webhooks):
    _deliver(client, "installation_repositories", _added(_repo("fresh"), _repo("keep")))
    _deliver(client, "installation_repositories", _removed(_repo("fresh")))
    assert [n["repo"] for n in await _notices(pool)] == ["keep"]


async def test_removed_then_added_again_is_a_new_notice(client, pool, signed_webhooks):
    _deliver(client, "installation_repositories", _added(_repo("fresh")))
    await repo_notices.dismiss(pool, OWNER, "fresh", dismissed_by=OPERATOR)
    _deliver(client, "installation_repositories", _removed(_repo("fresh")))
    _deliver(client, "installation_repositories", _added(_repo("fresh")))
    assert [(n["repo"], n["dismissed"]) for n in await _notices(pool)] == [("fresh", False)]


async def test_installing_the_app_announces_its_repositories(client, pool, signed_webhooks):
    _deliver(client, "installation", {"action": "created", "installation": {"id": 1},
                                      "repositories": [_repo("one"), _repo("two")]})
    assert [n["repo"] for n in await _notices(pool)] == ["one", "two"]


async def test_uninstalling_the_app_clears_its_notices(client, pool, signed_webhooks):
    _deliver(client, "installation", {"action": "created", "installation": {"id": 1},
                                      "repositories": [_repo("one"), _repo("two")]})
    _deliver(client, "installation", {"action": "deleted", "installation": {"id": 1},
                                      "repositories": [_repo("one"), _repo("two")]})
    assert await _notices(pool) == []


async def test_an_unsigned_delivery_creates_nothing(client, pool, signed_webhooks):
    resp = _deliver(client, "installation_repositories", _added(_repo("fresh")), secret="wrong")
    assert resp.status_code == 401
    assert await _notices(pool) == []


async def test_an_added_repository_is_not_hidden_by_the_hour_long_installed_cache(client, pool, signed_webhooks):
    """installed_repositories() is cached for an hour, and an installation
    lookup for the repo may be cached as "not installed". Both are dropped
    on the event, or the new repository would be missing from the page it
    is announced on for up to an hour."""
    access._installed_cache["all"] = (time.monotonic(), [])
    access._installation_cache[(OWNER, "fresh")] = (time.monotonic(), None)
    _deliver(client, "installation_repositories", _added(_repo("fresh")))
    assert "all" not in access._installed_cache
    assert (OWNER, "fresh") not in access._installation_cache


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------

async def test_the_operator_sees_the_notice_with_its_three_actions(client, pool, as_principal):
    await repo_notices.announce(pool, [(OWNER, "fresh", False)])
    as_principal(OPERATOR, audit_principals=OPERATOR)
    block = _notice_block(_page(client, "fresh"))

    assert "New repository: <a" in block and f"{OWNER}/fresh" in block
    assert f'action="/dashboard/repos/{OWNER}/fresh/audit"' in block and "Run audit" in block
    assert f'action="/dashboard/repos/{OWNER}/fresh/pr-reviews"' in block and "Turn on PR reviews" in block
    assert f'action="/dashboard/notices/{OWNER}/fresh/dismiss"' in block and "Dismiss" in block
    assert block.count('name="csrf_token"') == 3


async def test_a_private_new_repository_offers_no_audit(client, pool, as_principal):
    await repo_notices.announce(pool, [(OWNER, "secret", True)])
    as_principal(OPERATOR, audit_principals=OPERATOR)
    block = _notice_block(_page(client, "secret"))
    assert "/audit" not in block and "Turn on PR reviews" in block


async def test_a_repository_already_reviewed_says_so_instead_of_offering_to_turn_it_on(client, pool, as_principal):
    from codeguard.api import repo_settings
    await repo_notices.announce(pool, [(OWNER, "fresh", False)])
    await repo_settings.set_pr_reviews(pool, OWNER, "fresh", enabled=True, updated_by=OPERATOR)
    as_principal(OPERATOR, audit_principals=OPERATOR)
    block = _notice_block(_page(client, "fresh"))
    assert "/pr-reviews" not in block and "PR reviews on" in block


async def test_a_non_operator_sees_no_notices(client, pool, as_principal):
    await repo_notices.announce(pool, [(OWNER, "fresh", False)])
    as_principal(VISITOR, audit_principals=OPERATOR)
    html = _page(client, "fresh")
    assert f"{OWNER}/fresh" in html  # the row renders, so the absence is not vacuous
    assert "repo-notices" not in html and "New repository" not in html


async def test_a_notice_for_a_repo_the_operator_cannot_access_is_not_shown(client, pool, as_principal):
    await repo_notices.announce(pool, [(OWNER, "fresh", False)])
    as_principal(OPERATOR, audit_principals=OPERATOR)
    assert "New repository" not in _page(client, "fresh", collaborator=False)


async def test_dismissed_notices_are_not_shown(client, pool, as_principal):
    await repo_notices.announce(pool, [(OWNER, "fresh", False), (OWNER, "other", False)])
    await repo_notices.dismiss(pool, OWNER, "fresh", dismissed_by=OPERATOR)
    as_principal(OPERATOR, audit_principals=OPERATOR)
    block = _notice_block(_page(client, "fresh", "other"))
    assert f"{OWNER}/other" in block and f"{OWNER}/fresh" not in block


async def test_several_notices_offer_dismiss_all_and_one_does_not(client, pool, as_principal):
    as_principal(OPERATOR, audit_principals=OPERATOR)
    await repo_notices.announce(pool, [(OWNER, "fresh", False)])
    assert "/dashboard/notices/dismiss-all" not in _page(client, "fresh")
    await repo_notices.announce(pool, [(OWNER, "other", False)])
    assert 'action="/dashboard/notices/dismiss-all"' in _page(client, "fresh", "other")


# --------------------------------------------------------------------------
# Dismissing
# --------------------------------------------------------------------------

async def test_the_operator_dismisses_a_notice_and_it_stays_dismissed(client, pool, as_principal):
    await repo_notices.announce(pool, [(OWNER, "fresh", False)])
    as_principal(OPERATOR, audit_principals=OPERATOR)
    resp = _post(client, f"/dashboard/notices/{OWNER}/fresh/dismiss")
    assert resp.status_code == 303 and resp.headers["location"] == "/dashboard/repos"
    assert await _notices(pool) == [
        {"owner": OWNER, "repo": "fresh", "private": False, "dismissed": True, "dismissed_by": OPERATOR}]
    assert "New repository" not in _page(client, "fresh")


async def test_dismiss_all(client, pool, as_principal):
    await repo_notices.announce(pool, [(OWNER, "a", False), (OWNER, "b", False)])
    as_principal(OPERATOR, audit_principals=OPERATOR)
    assert _post(client, "/dashboard/notices/dismiss-all").status_code == 303
    assert all(n["dismissed"] for n in await _notices(pool))


@pytest.mark.parametrize("path", [f"/dashboard/notices/{OWNER}/fresh/dismiss", "/dashboard/notices/dismiss-all"])
async def test_a_non_operator_gets_404_and_nothing_is_dismissed(client, pool, as_principal, path):
    await repo_notices.announce(pool, [(OWNER, "fresh", False)])
    as_principal(VISITOR, audit_principals=OPERATOR)
    assert _post(client, path).status_code == 404
    assert not (await _notices(pool))[0]["dismissed"]


@pytest.mark.parametrize("path", [f"/dashboard/notices/{OWNER}/fresh/dismiss", "/dashboard/notices/dismiss-all"])
async def test_an_anonymous_visitor_gets_404(anon_client, pool, path):
    await repo_notices.announce(pool, [(OWNER, "fresh", False)])
    resp = anon_client.post(path, headers={"Origin": "http://testserver"}, follow_redirects=False)
    assert resp.status_code == 404
    assert not (await _notices(pool))[0]["dismissed"]


async def test_the_operator_without_a_csrf_token_gets_403(client, pool, as_principal):
    await repo_notices.announce(pool, [(OWNER, "fresh", False)])
    as_principal(OPERATOR, audit_principals=OPERATOR)
    assert _post(client, f"/dashboard/notices/{OWNER}/fresh/dismiss", token="").status_code == 403
    assert not (await _notices(pool))[0]["dismissed"]
