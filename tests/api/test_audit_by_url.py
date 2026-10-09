"""Audit a public repository by URL, from the Repositories page.

Operators only (404 for anyone else), CSRF-checked. The URL goes through
the existing gates, unchanged: parse_public_github_url (strict, no network)
and verify_public_and_sized (GitHub says public and small enough), then the
same queueing, deadline and budget cap as Run audit.

Readable by the REQUESTER ONLY, other operators included, and with no
repo-access check: the repository need not have the App installed, and
"may this person access the repo" goes through the installation, so the
old rule made such an audit unreadable even by the person who ran it.

GitHub is mocked throughout. No clone, no live call.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest

from codeguard.api import access, audits, csrf, repo_url

OPERATOR = "ashrithaumd"
OTHER_OPERATOR = "ashrithapola"
VISITOR = "someone-else"
TARGET_OWNER = "simonw"
TARGET_REPO = "llm"
URL = f"https://github.com/{TARGET_OWNER}/{TARGET_REPO}"


@pytest.fixture
def github_says_public():
    with patch("codeguard.api.repo_url.verify_public_and_sized",
               return_value={"private": False, "size": 1000}) as m:
        yield m


def _post(client, url=URL, token=None):
    client.get("/dashboard")
    return client.post(
        "/dashboard/repos/audit-url",
        data={"url": url,
              "csrf_token": client.cookies.get(csrf.COOKIE_NAME, "") if token is None else token},
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )


async def _counts(pool):
    async with pool.connection() as conn:
        a = await (await conn.execute("SELECT count(*) AS n FROM audits")).fetchone()
        j = await (await conn.execute("SELECT count(*) AS n FROM jobs")).fetchone()
    return a["n"], j["n"]


async def _url_audit(pool, requested_by=OPERATOR, owner=TARGET_OWNER, repo=TARGET_REPO, status="done"):
    audit = await audits.request_audit(pool, owner=owner, repo=repo, requested_by=requested_by,
                                       private=False, by_url=True)
    if status == "done":
        await audits.finish_audit(pool, audit["id"], status="done", report_markdown="# r\n", report_json=None)
    return audit["id"]


def _no_access():
    """The App is not installed on the target, so GitHub's collaborator
    answer through the installation is 'no' for everybody."""
    return patch.object(access, "_is_collaborator", return_value=False)


# --------------------------------------------------------------------------
# Requesting
# --------------------------------------------------------------------------

async def test_the_operator_queues_an_audit_by_url(client, pool, as_principal, github_says_public):
    as_principal(OPERATOR, audit_principals=OPERATOR)
    with _no_access():
        resp = _post(client)

    assert resp.status_code == 303
    audit_id = resp.headers["location"].rsplit("/", 1)[-1]
    async with pool.connection() as conn:
        row = await (await conn.execute(
            "SELECT owner, repo, requested_by, private, by_url, status FROM audits WHERE id = %s",
            (audit_id,))).fetchone()
        job = await (await conn.execute(
            "SELECT type, payload FROM jobs WHERE id = (SELECT job_id FROM audits WHERE id = %s)",
            (audit_id,))).fetchone()
    assert dict(row) == {"owner": TARGET_OWNER, "repo": TARGET_REPO, "requested_by": OPERATOR,
                         "private": False, "by_url": True, "status": "queued"}
    assert job["type"] == "repo_audit" and job["payload"]["target"] == URL
    github_says_public.assert_called_once_with(TARGET_OWNER, TARGET_REPO)


async def test_a_signed_in_non_operator_gets_404(client, pool, as_principal, github_says_public):
    as_principal(VISITOR, audit_principals=OPERATOR)
    assert _post(client).status_code == 404
    assert await _counts(pool) == (0, 0)
    github_says_public.assert_not_called()


async def test_an_anonymous_visitor_gets_404(anon_client, pool, github_says_public):
    resp = anon_client.post("/dashboard/repos/audit-url", data={"url": URL},
                            headers={"Origin": "http://testserver"}, follow_redirects=False)
    assert resp.status_code == 404
    assert await _counts(pool) == (0, 0)


async def test_the_operator_without_a_csrf_token_gets_403(client, pool, as_principal, github_says_public):
    as_principal(OPERATOR, audit_principals=OPERATOR)
    assert _post(client, token="").status_code == 403
    assert await _counts(pool) == (0, 0)
    github_says_public.assert_not_called()


@pytest.mark.parametrize("bad, says", [
    ("http://github.com/simonw/llm", "https://"),
    ("https://gitlab.com/simonw/llm", "github.com"),
    ("https://user:pw@github.com/simonw/llm", ""),
    ("https://github.com:8443/simonw/llm", ""),
    ("https://github.com/simonw/llm?tab=readme", "query"),
    ("https://github.com/simonw/../etc", ""),
    ("git@github.com:simonw/llm.git", ""),
    ("", "Please paste"),
])
async def test_a_url_the_strict_parser_refuses_is_400_and_costs_no_github_call(
        client, pool, as_principal, github_says_public, bad, says):
    as_principal(OPERATOR, audit_principals=OPERATOR)
    resp = _post(client, url=bad)
    assert resp.status_code == 400
    assert says in resp.text
    assert await _counts(pool) == (0, 0)
    github_says_public.assert_not_called()


async def test_a_private_or_missing_repository_is_refused_with_a_clear_message(client, pool, as_principal):
    as_principal(OPERATOR, audit_principals=OPERATOR)
    with patch("codeguard.api.repo_url.verify_public_and_sized",
               side_effect=repo_url.RepoRejected(repo_url.NOT_FOUND_MESSAGE)):
        resp = _post(client, url="https://github.com/ashrithaumd/secret-thing")
    assert resp.status_code == 400
    assert "can only audit public repositories" in resp.text
    assert await _counts(pool) == (0, 0)


async def test_an_oversized_repository_is_refused_and_nothing_is_queued(client, pool, as_principal):
    as_principal(OPERATOR, audit_principals=OPERATOR)
    with patch("codeguard.api.repo_url.verify_public_and_sized",
               side_effect=repo_url.RepoRejected("This repository is too large to audit (900 MB).")):
        resp = _post(client)
    assert resp.status_code == 400 and "too large" in resp.text
    assert await _counts(pool) == (0, 0)


async def test_a_second_request_while_one_runs_goes_to_the_running_one(client, pool, as_principal,
                                                                       github_says_public):
    as_principal(OPERATOR, audit_principals=OPERATOR)
    running = await _url_audit(pool, repo="other", status="queued")
    resp = _post(client)
    assert resp.status_code == 303 and resp.headers["location"] == f"/dashboard/audits/{running}"
    assert (await _counts(pool))[0] == 1


# --------------------------------------------------------------------------
# Reading: the requester only, and no repo-access check
# --------------------------------------------------------------------------

async def test_the_requester_can_read_an_audit_of_a_repo_without_the_app(client, pool, as_principal):
    """Regression: _may_read_audit asked can_access_repo first, which goes
    through the App's installation, so nobody -- not even the requester --
    could open an audit of a repository the App is not installed on."""
    audit_id = await _url_audit(pool)
    as_principal(OPERATOR, audit_principals=OPERATOR)
    with _no_access():
        assert client.get(f"/dashboard/audits/{audit_id}").status_code == 200
        assert client.get(f"/dashboard/audits/{audit_id}.json").status_code == 200


async def test_another_operator_cannot_read_it(client, pool, as_principal):
    audit_id = await _url_audit(pool)
    as_principal(OTHER_OPERATOR, audit_principals=f"{OPERATOR},{OTHER_OPERATOR}")
    with patch.object(access, "_is_collaborator", return_value=True):
        assert client.get(f"/dashboard/audits/{audit_id}").status_code == 404
        assert client.get(f"/dashboard/audits/{audit_id}.json").status_code == 404


async def test_a_signed_in_visitor_cannot_read_it(client, pool, as_principal):
    audit_id = await _url_audit(pool)
    as_principal(VISITOR, audit_principals=OPERATOR)
    with patch.object(access, "_is_collaborator", return_value=True):
        assert client.get(f"/dashboard/audits/{audit_id}").status_code == 404


async def test_an_anonymous_visitor_cannot_read_it(anon_client, pool):
    audit_id = await _url_audit(pool)
    assert anon_client.get(f"/dashboard/audits/{audit_id}").status_code == 404


async def test_the_requester_matches_case_insensitively(client, pool, as_principal):
    audit_id = await _url_audit(pool, requested_by="AshrithaUMD")
    as_principal(OPERATOR, audit_principals=OPERATOR)
    with _no_access():
        assert client.get(f"/dashboard/audits/{audit_id}").status_code == 200


async def test_an_installed_repo_audit_keeps_the_old_rule(client, pool, as_principal):
    """Not by URL: repo access is still required, and an operator may still
    read another person's audit of an installed repository."""
    audit = await audits.request_audit(pool, owner="ashrithaumd", repo="reliqueue",
                                       requested_by=VISITOR, private=False)
    as_principal(OPERATOR, audit_principals=OPERATOR)
    with patch.object(access, "_is_collaborator", return_value=True):
        access.reset_caches()
        assert client.get(f"/dashboard/audits/{audit['id']}").status_code == 200
    with _no_access():
        access.reset_caches()
        assert client.get(f"/dashboard/audits/{audit['id']}").status_code == 404


async def test_the_audit_page_links_the_repository_to_github_not_to_a_repo_page(client, pool, as_principal):
    audit_id = await _url_audit(pool)
    as_principal(OPERATOR, audit_principals=OPERATOR)
    with _no_access():
        html = client.get(f"/dashboard/audits/{audit_id}").text
    assert f'href="https://github.com/{TARGET_OWNER}/{TARGET_REPO}"' in html
    assert f'href="/dashboard/repos/{TARGET_OWNER}/{TARGET_REPO}"' not in html


# --------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------

def _page(client):
    with patch.object(access, "installed_repositories", return_value=[]), \
         patch.object(access, "_is_collaborator", return_value=True):
        return client.get("/dashboard/repos").text


async def test_the_operator_sees_the_url_input(client, pool, as_principal):
    as_principal(OPERATOR, audit_principals=OPERATOR)
    html = _page(client)
    form = html[html.index('action="/dashboard/repos/audit-url"'):]
    form = form[:form.index("</form>")]
    assert 'name="url"' in form and 'name="csrf_token"' in form


async def test_a_non_operator_sees_no_url_input(client, pool, as_principal):
    as_principal(VISITOR, audit_principals=OPERATOR)
    html = _page(client)
    assert "Repositories" in html
    assert "audit-url" not in html


async def test_your_audits_by_url_lists_only_your_own(client, pool, as_principal):
    await _url_audit(pool, repo="mine")
    await _url_audit(pool, requested_by=OTHER_OPERATOR, repo="theirs")
    as_principal(OPERATOR, audit_principals=f"{OPERATOR},{OTHER_OPERATOR}")
    html = _page(client)
    block = html[html.index('class="panel url-audits"'):]
    block = block[:block.index("</section>")]
    assert f"{TARGET_OWNER}/mine" in block
    assert "theirs" not in html


async def test_another_operators_page_does_not_list_my_url_audits(client, pool, as_principal):
    await _url_audit(pool, repo="mine")
    as_principal(OTHER_OPERATOR, audit_principals=f"{OPERATOR},{OTHER_OPERATOR}")
    assert f"{TARGET_OWNER}/mine" not in _page(client)


async def test_ids_are_not_guessable_into_someone_elses_audit(client, pool, as_principal):
    """A made-up id is the same 404 as someone else's: no oracle."""
    as_principal(OTHER_OPERATOR, audit_principals=f"{OPERATOR},{OTHER_OPERATOR}")
    assert client.get(f"/dashboard/audits/{uuid.uuid4()}").status_code == 404


@pytest.mark.parametrize("owner, repo, expected", [
    ("simonw", "llm", "https://github.com/simonw/llm"),
    ("simonw", "llm/../x", None),
    ("simonw", 'llm" onclick="x', None),
    ("", "llm", None),
])
def test_the_github_link_is_built_only_from_github_names(owner, repo, expected):
    from codeguard.api.display import github_repo_url
    assert github_repo_url(owner, repo) == expected
