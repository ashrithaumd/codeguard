"""The audit POST must not be triggerable from another site.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
`POST /dashboard/repos/{owner}/{repo}/audit` was authorized purely by
who the caller is. Identity arrives in a COOKIE (EasyAuth's session,
which the browser attaches to any request to our origin), so a form on
any page the operator visits:

    <form method="post"
          action="https://codeguard-api.../dashboard/repos/o/r/audit">

submitted by script while they are signed in, is indistinguishable at
the route from the operator clicking "Run audit" themselves. That is
CSRF, and here it is not a theoretical annoyance:

  * an audit clones a repository and spends the operator's Anthropic
    credit, so a page can bill them
  * one audit per user may be in flight, so an attacker can hold that
    slot and lock the operator out of their own audits
  * the attacker cannot read the result -- audits are visible only to
    their requester -- which makes this a spend-and-denial attack, not
    an exfiltration one. That is still worth stopping.

TWO INDEPENDENT CHECKS, because each covers the other's weakness:

  1. ORIGIN. A cross-site POST carries the attacker's Origin, and script
     cannot forge that header. But an Origin-only check fails open on any
     client that omits it.
  2. A DOUBLE-SUBMIT TOKEN. A random value in a SameSite=Strict cookie,
     echoed in a hidden form field; an attacker's page cannot read our
     cookie to put the right value in its form. But a cookie-setting
     attacker on a sibling host of a shared parent domain could plant
     both halves -- and this app is deployed on
     *.azurecontainerapps.io, a domain it shares with other tenants.
     The Origin check is what covers that, since their Origin still
     differs.

Neither is sufficient alone here. Both are cheap.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from codeguard.api import access, csrf
from codeguard.config import Settings, get_settings

OWNER = "ashrithaumd"
PUBLIC = "codeguard-playground"
STRANGER = "someone-else"

AUDIT_URL = f"/dashboard/repos/{OWNER}/{PUBLIC}/audit"
# TestClient's own origin. A same-origin POST looks like this.
OURS = "http://testserver"
THEIRS = "https://evil.example.com"


def _installed():
    return [{
        "owner": OWNER, "repo": PUBLIC, "private": False,
        "installation_id": 4934663,
        "html_url": f"https://github.com/{OWNER}/{PUBLIC}",
    }]


# as_principal now lives in tests/api/conftest.py. It was duplicated in
# three files, and the operator allow-list moving to numeric GitHub ids
# meant all three needed the same login -> id mapping -- three copies of
# which is three chances for one file to mean "the operator" while
# another means somebody else.


@pytest.fixture
def repo_is_public(monkeypatch):
    monkeypatch.setattr(
        "codeguard.api.repo_url.verify_public_and_sized",
        lambda owner, repo: {"private": False, "size": 100},
    )


def _token_for(client) -> str:
    """Obtain a token the way a browser does: load a page, keep the cookie.

    Deliberately NOT by calling the minting function. A token the tests
    invent could pass a check that a real page's token would fail -- the
    cookie the server actually sets is the thing under test.
    """
    client.get("/dashboard")
    return client.cookies[csrf.COOKIE_NAME]


async def _count_audits(pool) -> int:
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT count(*) AS n FROM audits")
        return (await cur.fetchone())["n"]


# --------------------------------------------------------------------------
# The refusals
# --------------------------------------------------------------------------


async def test_a_cross_site_post_is_refused(client, pool, as_principal, repo_is_public):
    """The regression. Everything is right except where the POST came
    from: the operator's own identity, a genuine token from their own
    cookie -- which an attacker's page could obtain only if it could read
    our cookies -- and a foreign Origin. Refused on the Origin alone."""
    as_principal(OWNER, audit_principals=OWNER)
    token = _token_for(client)

    with patch.object(access, "installed_repositories", return_value=_installed()):
        resp = client.post(
            AUDIT_URL, data={"csrf_token": token},
            headers={"Origin": THEIRS}, follow_redirects=False,
        )

    assert resp.status_code == 403
    assert await _count_audits(pool) == 0, "a refused POST must queue nothing"


async def test_a_post_with_no_token_is_refused(client, pool, as_principal, repo_is_public):
    """The Origin is ours but the form carries nothing. This is the shape
    a curl-driven replay takes, and the shape a cross-site POST takes when
    the browser omits Origin."""
    as_principal(OWNER, audit_principals=OWNER)
    _token_for(client)

    with patch.object(access, "installed_repositories", return_value=_installed()):
        resp = client.post(AUDIT_URL, headers={"Origin": OURS}, follow_redirects=False)

    assert resp.status_code == 403
    assert await _count_audits(pool) == 0


async def test_a_post_with_a_wrong_token_is_refused(client, pool, as_principal, repo_is_public):
    as_principal(OWNER, audit_principals=OWNER)
    _token_for(client)

    with patch.object(access, "installed_repositories", return_value=_installed()):
        resp = client.post(
            AUDIT_URL, data={"csrf_token": "0" * 64},
            headers={"Origin": OURS}, follow_redirects=False,
        )

    assert resp.status_code == 403
    assert await _count_audits(pool) == 0


async def test_a_post_with_no_cookie_at_all_is_refused(client, pool, as_principal, repo_is_public):
    """Half of a double-submit is not a submit. A token in the form with
    no cookie to compare it against must fail closed -- the tempting bug
    is to treat "nothing to compare" as "nothing to object to"."""
    as_principal(OWNER, audit_principals=OWNER)
    token = _token_for(client)
    client.cookies.clear()

    with patch.object(access, "installed_repositories", return_value=_installed()):
        resp = client.post(
            AUDIT_URL, data={"csrf_token": token},
            headers={"Origin": OURS}, follow_redirects=False,
        )

    assert resp.status_code == 403
    assert await _count_audits(pool) == 0


async def test_a_cross_site_referer_is_refused_when_origin_is_absent(
    client, pool, as_principal, repo_is_public,
):
    """Origin is the primary signal, Referer the fallback. A client that
    sends only Referer still gets checked."""
    as_principal(OWNER, audit_principals=OWNER)
    token = _token_for(client)

    with patch.object(access, "installed_repositories", return_value=_installed()):
        resp = client.post(
            AUDIT_URL, data={"csrf_token": token},
            headers={"Referer": f"{THEIRS}/attack"}, follow_redirects=False,
        )

    assert resp.status_code == 403
    assert await _count_audits(pool) == 0


# --------------------------------------------------------------------------
# What must still work
# --------------------------------------------------------------------------


async def test_the_legitimate_post_from_our_own_page_succeeds(
    client, pool, as_principal, repo_is_public,
):
    """The control has to let the real thing through, or it is just an
    outage. Same origin, token from our own cookie."""
    as_principal(OWNER, audit_principals=OWNER)
    token = _token_for(client)

    with patch.object(access, "installed_repositories", return_value=_installed()):
        resp = client.post(
            AUDIT_URL, data={"csrf_token": token},
            headers={"Origin": OURS}, follow_redirects=False,
        )

    assert resp.status_code == 303, resp.text
    assert await _count_audits(pool) == 1


async def test_a_post_with_neither_origin_nor_referer_is_allowed_with_a_good_token(
    client, pool, as_principal, repo_is_public,
):
    """A deliberate, narrow allowance, so the reasoning is recorded rather
    than left to be re-derived.

    Some clients omit both headers. Rejecting on absence would break them;
    accepting on absence is safe ONLY because the token still has to
    match, and a cross-site attacker cannot read our cookie to supply it.
    This is the case the token layer exists for.
    """
    as_principal(OWNER, audit_principals=OWNER)
    token = _token_for(client)

    with patch.object(access, "installed_repositories", return_value=_installed()):
        resp = client.post(AUDIT_URL, data={"csrf_token": token}, follow_redirects=False)

    assert resp.status_code == 303, resp.text


# --------------------------------------------------------------------------
# The cookie and the form
# --------------------------------------------------------------------------


def test_the_cookie_is_issued_on_a_page_load(client):
    resp = client.get("/dashboard")
    assert csrf.COOKIE_NAME in resp.cookies


def test_the_cookie_is_samesite_strict_and_http_only(client):
    """SameSite=Strict is a third layer under the other two: a browser
    that honours it will not attach the cookie to a cross-site POST at
    all, so the token cannot match even before our check runs. HttpOnly
    because the template renders the token server-side -- no script needs
    to read it, so nothing should be able to."""
    resp = client.get("/dashboard")
    header = resp.headers["set-cookie"]

    assert "samesite=strict" in header.lower()
    assert "httponly" in header.lower()
    assert "path=/" in header.lower()


def test_the_cookie_is_stable_across_requests(client):
    """A token that changed on every render would break the second tab,
    and the back button."""
    first = _token_for(client)
    client.get("/dashboard")
    assert client.cookies[csrf.COOKIE_NAME] == first


async def test_the_form_carries_the_token(client, as_principal):
    """The token has to actually reach the page, or every real click is a
    403 while this suite passes."""
    as_principal(OWNER, audit_principals=OWNER)
    with patch.object(access, "installed_repositories", return_value=_installed()), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    token = client.cookies[csrf.COOKIE_NAME]
    assert 'name="csrf_token"' in resp.text
    assert token in resp.text


# --------------------------------------------------------------------------
# Ordering: the CSRF failure must not be more informative than the
# authorization failure
# --------------------------------------------------------------------------


async def test_an_unauthorised_caller_still_gets_404_not_403(
    client, pool, as_principal, repo_is_public,
):
    """Check order is load-bearing.

    This route answers 404 to anyone who may not audit, so that a 403
    does not confirm an audit facility is there to be found. If the CSRF
    check ran first, a stranger sending a bad token would get 403 and
    learn exactly that. Authorization first, CSRF second.
    """
    as_principal(STRANGER, audit_principals=OWNER)

    with patch.object(access, "installed_repositories", return_value=_installed()):
        resp = client.post(
            AUDIT_URL, data={"csrf_token": "0" * 64},
            headers={"Origin": THEIRS}, follow_redirects=False,
        )

    assert resp.status_code == 404
    assert await _count_audits(pool) == 0


async def test_a_refused_post_never_reaches_github(client, pool, as_principal):
    """The precheck costs a GitHub API call, so the CSRF gate must come
    before it -- otherwise a cross-site POST can still burn rate limit."""
    as_principal(OWNER, audit_principals=OWNER)
    token = _token_for(client)

    calls: list[tuple[str, str]] = []

    def _record(owner, repo):
        calls.append((owner, repo))
        return {"private": False, "size": 100}

    with patch.object(access, "installed_repositories", return_value=_installed()), \
         patch("codeguard.api.repo_url.verify_public_and_sized", _record):
        resp = client.post(
            AUDIT_URL, data={"csrf_token": token},
            headers={"Origin": THEIRS}, follow_redirects=False,
        )

    assert resp.status_code == 403
    assert calls == [], "a refused POST must not spend a GitHub API call"


# --------------------------------------------------------------------------
# Defence in depth: a route added later must not silently skip the check
# --------------------------------------------------------------------------


def test_every_state_changing_dashboard_route_verifies_csrf():
    """Structural, and deliberately so.

    The check lives in the handler rather than in middleware, because
    middleware runs BEFORE the authorization gate and would answer 403 to a
    caller this module owes a 404 (see the test above). The cost of that
    choice is that a new POST route can forget to call it, and nothing
    would fail -- the route would simply be forgeable.

    So this asserts the property over the router rather than over one
    route: every handler reachable by an unsafe method mentions
    csrf.verify. Inspecting source is crude; it is also the only thing that
    fails when someone adds a second POST here and does not read this file.
    """
    import inspect

    from codeguard.api.routes import dashboard

    unsafe = {"POST", "PUT", "PATCH", "DELETE"}
    checked, missing = [], []
    for route in dashboard.router.routes:
        methods = getattr(route, "methods", set()) or set()
        if not (methods & unsafe):
            continue
        source = inspect.getsource(route.endpoint)
        (checked if "csrf.verify" in source else missing).append(route.path)

    assert checked, "no unsafe dashboard route found -- has the router moved?"
    assert missing == [], (
        f"these dashboard routes change state without verifying CSRF: {missing}"
    )
