"""The Repositories page, the audit trigger, and the concurrency lock.

The tests that matter most here are the negative ones. This page is the
first in the dashboard whose repository list does NOT originate in a
review row — it comes from GitHub's installed-repositories endpoint,
which returns private repository names because the App can see them,
not because the viewer can. And the audit button spends the operator's
own money, so its gate is the only thing standing between a signed-in
stranger and an arbitrary bill.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from codeguard.api import access
from codeguard.config import Settings, get_settings
from tests.api.conftest import insert_review

OWNER = "ashrithaumd"
PUBLIC = "codeguard-playground"
PRIVATE = "secret-thing"

OWNER_LOGIN = "ashrithaumd"
STRANGER = "someone-else"


def _installed(*entries):
    return [
        {"owner": owner, "repo": repo, "private": private,
         "installation_id": 4934663, "html_url": f"https://github.com/{owner}/{repo}"}
        for owner, repo, private in entries
    ]


@pytest.fixture
def as_principal(monkeypatch):
    """Sign a visitor in without EasyAuth, via the existing dev override.

    Uses the two-key form the setting already requires — a username AND
    an explicit trust flag — rather than injecting the header directly,
    so the test exercises the same path a local dev run does.
    """
    def _sign_in(login: str | None, *, audit_principals: str = ""):
        base = get_settings().model_dump()
        base.update({
            "dashboard_dev_principal": login or "",
            "dashboard_trust_dev_principal": bool(login),
            "dashboard_audit_principals": audit_principals,
        })
        patched = Settings(**base)
        monkeypatch.setattr("codeguard.api.auth.get_settings", lambda: patched)
        monkeypatch.setattr("codeguard.api.routes.dashboard.get_settings", lambda: patched)
        return patched
    return _sign_in


# --------------------------------------------------------------------------
# Listing
# --------------------------------------------------------------------------

async def test_an_installed_repo_with_no_reviews_still_appears(client, pool, as_principal):
    """"Installed but never reviewed" is a real state — usually "no pull
    request opened yet" — and hiding it would make this page disagree
    with GitHub's own installation settings, which is where the page's
    own button sends you."""
    as_principal(OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.get("/dashboard/repos")

    assert resp.status_code == 200
    assert f"{OWNER}/{PUBLIC}" in resp.text
    assert "Never" in resp.text


async def test_a_private_repo_is_hidden_from_someone_who_cannot_see_it(
    client, pool, as_principal,
):
    """The disclosure this page could cause and the reviews pages could
    not: /installation/repositories hands us private repo NAMES, and
    nothing about that endpoint is scoped to the viewer."""
    as_principal(STRANGER)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PRIVATE, True))), \
         patch.object(access, "_is_collaborator", return_value=False):
        resp = client.get("/dashboard/repos")

    assert resp.status_code == 200
    assert PRIVATE not in resp.text


async def test_a_private_repo_is_shown_to_a_collaborator(client, pool, as_principal):
    as_principal(OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PRIVATE, True))), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    assert resp.status_code == 200
    assert PRIVATE in resp.text


async def test_review_stats_are_rolled_up_per_repo(client, pool, as_principal):
    await insert_review(pool, owner=OWNER, repo=PUBLIC, private=False, estimated_cost_usd=0.01)
    await insert_review(pool, owner=OWNER, repo=PUBLIC, private=False, estimated_cost_usd=0.02)
    as_principal(OWNER_LOGIN)

    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.get("/dashboard/repos")

    assert resp.status_code == 200
    assert "$0.03" in resp.text or "0.03" in resp.text


async def test_a_github_failure_falls_back_without_inventing_repos(
    client, pool, as_principal,
):
    """Fail closed on the question we could not answer, not on the page.

    The fallback list is strictly narrower — repos that already have
    review rows — so it can never surface something the real list would
    not have. The banner is what stops an incomplete list reading as
    "you have not installed CodeGuard anywhere".
    """
    await insert_review(pool, owner=OWNER, repo=PUBLIC, private=False)
    as_principal(OWNER_LOGIN)

    with patch.object(access, "installed_repositories",
                      side_effect=access.InstallationLookupFailed("boom")):
        resp = client.get("/dashboard/repos")

    assert resp.status_code == 200
    assert "Couldn't reach GitHub" in resp.text
    assert f"{OWNER}/{PUBLIC}" in resp.text
    assert "Unknown" in resp.text


async def test_signed_in_landing_redirects_to_repositories(client, as_principal):
    as_principal(OWNER_LOGIN)
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard/repos"


async def test_a_filtered_dashboard_url_is_not_redirected(client, pool, as_principal):
    """Every shared or bookmarked dashboard link carries query
    parameters. A blanket redirect would silently drop the filters,
    which is the whole thing putting them in the query string bought."""
    as_principal(OWNER_LOGIN)
    resp = client.get("/dashboard?severity=HIGH", follow_redirects=False)
    assert resp.status_code == 200


async def test_an_anonymous_visitor_is_not_redirected(client):
    resp = client.get("/dashboard", follow_redirects=False)
    assert resp.status_code == 200


# --------------------------------------------------------------------------
# The audit gate
# --------------------------------------------------------------------------

async def test_audit_is_refused_for_a_signed_in_stranger(client, pool, as_principal):
    """The requirement in one test: gated to a named principal, not to
    "anyone who completed a GitHub login". An audit clones a repository
    and spends the operator's Anthropic credit."""
    as_principal(STRANGER, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)

    assert resp.status_code == 404


async def test_audit_is_refused_when_nobody_is_allowed(client, pool, as_principal):
    """The unset default. A deployment that never configures the
    allow-list must not hand the button to everyone."""
    as_principal(OWNER_LOGIN, audit_principals="")
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)

    assert resp.status_code == 404


async def test_audit_is_refused_for_an_anonymous_visitor(client, pool, as_principal):
    as_principal(None, audit_principals=OWNER_LOGIN)
    resp = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)
    assert resp.status_code == 404


async def test_the_button_is_absent_for_a_user_who_may_not_audit(
    client, pool, as_principal,
):
    as_principal(STRANGER, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.get("/dashboard/repos")

    # The form's action, not the button's label: base.html's row-link
    # script mentions "Run audit" in a comment, so matching the label
    # would pass or fail on the wording of a comment.
    assert f"/dashboard/repos/{OWNER}/{PUBLIC}/audit" not in resp.text


async def test_the_button_is_present_for_the_allowed_principal(
    client, pool, as_principal,
):
    as_principal(OWNER_LOGIN, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.get("/dashboard/repos")

    assert f"/dashboard/repos/{OWNER}/{PUBLIC}/audit" in resp.text


async def test_the_allow_list_is_case_insensitive(client, pool, as_principal):
    """GitHub logins are case-insensitive, so an allow-list that is not
    would deny the right person for the wrong reason."""
    as_principal("AshrithaUMD", audit_principals="ashrithaumd")
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)

    assert resp.status_code == 303


async def test_a_private_repo_cannot_be_audited(client, pool, as_principal):
    """A capability limit, not a permission one: run_audit clones over
    HTTPS and echoes the target into logs and stored error text, so a
    credentialed clone URL would leak."""
    as_principal(OWNER_LOGIN, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PRIVATE, True))), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.post(f"/dashboard/repos/{OWNER}/{PRIVATE}/audit", follow_redirects=False)

    assert resp.status_code == 400
    # The dashboard error handler renders HTML for /dashboard paths (see
    # api/main.py), so the reason is in the body, not a JSON field.
    assert "Private repositories" in resp.text


# --------------------------------------------------------------------------
# Concurrency
# --------------------------------------------------------------------------

async def test_a_second_audit_redirects_to_the_one_already_running(
    client, pool, as_principal,
):
    """The money question. Two tabs, a double click, or a retried POST
    must not produce two clones and two lots of spend for one repo. The
    partial unique index decides, not a check in the route."""
    as_principal(OWNER_LOGIN, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        first = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)
        second = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)

    assert first.status_code == 303
    assert second.status_code == 303
    # Same audit, so the second click is a redirect to the first one's
    # page rather than a second job.
    assert first.headers["location"] == second.headers["location"]

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT count(*) AS n FROM audits")
            assert (await cur.fetchone())["n"] == 1
            await cur.execute("SELECT count(*) AS n FROM jobs WHERE type = 'repo_audit'")
            assert (await cur.fetchone())["n"] == 1


async def test_a_repo_can_be_audited_again_once_the_first_finishes(
    client, pool, as_principal,
):
    """The index is partial on the in-flight states, so it constrains
    CONCURRENCY, not history."""
    from codeguard.api import audits as audits_mod

    as_principal(OWNER_LOGIN, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        first = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)
        audit_id = first.headers["location"].rsplit("/", 1)[-1]
        await audits_mod.finish_audit(pool, audit_id, status="done", report_markdown="# ok")
        second = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)

    assert second.headers["location"] != first.headers["location"]
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT count(*) AS n FROM audits")
            assert (await cur.fetchone())["n"] == 2


async def test_the_enqueued_job_carries_what_the_worker_needs(
    client, pool, as_principal,
):
    as_principal(OWNER_LOGIN, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)

    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT type, payload FROM jobs WHERE type = 'repo_audit'")
            row = await cur.fetchone()

    assert row["type"] == "repo_audit"
    assert row["payload"]["target"] == f"https://github.com/{OWNER}/{PUBLIC}"
    assert row["payload"]["owner"] == OWNER
    assert "audit_id" in row["payload"]


# --------------------------------------------------------------------------
# Progress and the report
# --------------------------------------------------------------------------

async def test_the_poll_endpoint_reports_terminal_state(client, pool, as_principal):
    from codeguard.api import audits as audits_mod

    as_principal(OWNER_LOGIN, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)
    audit_id = resp.headers["location"].rsplit("/", 1)[-1]

    queued = client.get(f"/dashboard/audits/{audit_id}.json").json()
    assert queued["status"] == "queued"
    assert queued["terminal"] is False

    await audits_mod.finish_audit(pool, audit_id, status="done", report_markdown="# report")
    done = client.get(f"/dashboard/audits/{audit_id}.json").json()
    assert done["status"] == "done"
    assert done["terminal"] is True


async def test_the_poll_payload_excludes_the_report(client, pool, as_principal):
    """A 2s poll must not re-send tens of kilobytes to say "still the
    same"."""
    from codeguard.api import audits as audits_mod

    as_principal(OWNER_LOGIN, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)
    audit_id = resp.headers["location"].rsplit("/", 1)[-1]
    await audits_mod.finish_audit(pool, audit_id, status="done", report_markdown="SECRET-REPORT")

    body = client.get(f"/dashboard/audits/{audit_id}.json").json()
    assert "SECRET-REPORT" not in str(body)
    assert "report_markdown" not in body


async def test_a_failed_audit_says_why(client, pool, as_principal):
    from codeguard.api import audits as audits_mod

    as_principal(OWNER_LOGIN, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)
    audit_id = resp.headers["location"].rsplit("/", 1)[-1]
    await audits_mod.finish_audit(
        pool, audit_id, status="failed", exit_code=1,
        error="git clone failed: repository not found",
    )

    page = client.get(f"/dashboard/audits/{audit_id}")
    assert page.status_code == 200
    assert "Why it failed" in page.text
    assert "repository not found" in page.text


async def test_the_audit_page_says_there_are_no_fix_suggestions(
    client, pool, as_principal,
):
    as_principal(OWNER_LOGIN, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)
    audit_id = resp.headers["location"].rsplit("/", 1)[-1]

    page = client.get(f"/dashboard/audits/{audit_id}")
    assert "no fix suggestions" in page.text.lower()


async def test_a_report_is_escaped_not_rendered_as_html(client, pool, as_principal):
    """The report contains scanner messages, which echo fragments of the
    scanned source — i.e. text the repository's authors control."""
    from codeguard.api import audits as audits_mod

    as_principal(OWNER_LOGIN, audit_principals=OWNER_LOGIN)
    with patch.object(access, "installed_repositories",
                      return_value=_installed((OWNER, PUBLIC, False))):
        resp = client.post(f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False)
    audit_id = resp.headers["location"].rsplit("/", 1)[-1]
    await audits_mod.finish_audit(
        pool, audit_id, status="done",
        report_markdown="<script>alert('xss')</script>",
    )

    page = client.get(f"/dashboard/audits/{audit_id}")
    assert "<script>alert" not in page.text
    assert "&lt;script&gt;" in page.text


async def test_an_audit_of_a_private_repo_is_404_for_a_stranger(
    client, pool, as_principal,
):
    from codeguard.api import audits as audits_mod

    audit = await audits_mod.request_audit(
        pool, owner=OWNER, repo=PRIVATE, requested_by=OWNER_LOGIN, private=True,
    )
    as_principal(STRANGER, audit_principals=OWNER_LOGIN)
    with patch.object(access, "_is_collaborator", return_value=False):
        page = client.get(f"/dashboard/audits/{audit['id']}")
        poll = client.get(f"/dashboard/audits/{audit['id']}.json")

    assert page.status_code == 404
    assert poll.status_code == 404


async def test_the_signed_in_landing_shows_setup_copy_when_nothing_is_installed(
    client, pool, as_principal,
):
    """The other half of test_dashboard_routes' setup-instructions test.

    That one now asks for the review log explicitly, because the landing
    view moved here. Somebody signing in for the first time must still
    be told what to do rather than shown an empty table, so the
    assertion moved with the view.
    """
    as_principal(OWNER_LOGIN)
    with patch.object(access, "installed_repositories", return_value=[]):
        resp = client.get("/dashboard", follow_redirects=True)

    assert resp.status_code == 200
    assert "No repositories yet" in resp.text
    assert "Add or remove a repository" in resp.text
