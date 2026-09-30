"""Every protection built under EasyAuth must still hold in "app" mode.

The point of this file is that the switch is not a rewrite of authorization —
only of where identity comes from. So each protection is re-asserted with a
signed session cookie standing in for the injected header, and the list is
deliberately the same list the migration prompt named:

    login-based identity, display name never deciding anything
    forged identity  -> tests/api/test_session.py (the cookie) and
                        tests/api/test_auth_mode.py (the header is ignored)
    CSRF on the audit POST
    security headers, including that the CSP does not block the GitHub redirect
    per-viewer access: anonymous sees nothing, others' audits 404
    /webhook, /health, /ready, /metrics stay outside sign-in

The two forged-identity files are separate because they are the replacement
for the platform property we are giving up, and they deserve to be read on
their own rather than buried in a carry-over list.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from codeguard.api import access, audits as audits_mod, csrf, session
from codeguard.config import Settings, get_settings

SECRET = "a-test-session-secret-long-enough-to-pass"

OWNER = "ashrithaumd"
OWNER_ID = "183667058"
STRANGER = "AshrithaPola"
STRANGER_ID = "60956648"
PUBLIC = "codeguard-playground"

AUDIT_URL = f"/dashboard/repos/{OWNER}/{PUBLIC}/audit"
OURS = "http://testserver"


@pytest.fixture
def app_mode(monkeypatch):
    def _configure(*, audit_ids: str = ""):
        base = get_settings().model_dump()
        base.update({
            "dashboard_auth_mode": "app",
            "session_secret": SECRET,
            "github_oauth_client_id": "Iv23liMt21lUXpodO0tx",
            "github_oauth_client_secret": "x",
            "dashboard_audit_principals": audit_ids,
            "dashboard_dev_principal": "", "dashboard_trust_dev_principal": False,
        })
        patched = Settings(**base)
        for target in ("codeguard.api.auth.get_settings",
                       "codeguard.api.oauth.get_settings",
                       "codeguard.api.routes.dashboard.get_settings"):
            monkeypatch.setattr(target, lambda: patched)
        return patched
    return _configure


def _sign_in(client, login=OWNER, user_id=OWNER_ID, display=None):
    """Put a genuine signed session in the client's jar."""
    value = session.issue(
        login=login, user_id=user_id, display_name=display or login, secret=SECRET,
    )
    client.cookies.set(session.COOKIE_NAME, value)
    return value


@pytest.fixture
def repo_is_public(monkeypatch):
    monkeypatch.setattr(
        "codeguard.api.repo_url.verify_public_and_sized",
        lambda owner, repo: {"private": False, "size": 100},
    )


def _installed():
    return [{"owner": OWNER, "repo": PUBLIC, "private": False,
             "installation_id": 4934663,
             "html_url": f"https://github.com/{OWNER}/{PUBLIC}"}]


# --- identity is the login; the display name decides nothing -------------


def test_the_login_gates_and_the_display_name_only_renders(client, app_mode):
    """The same property as under EasyAuth, now carried by the cookie: a
    display name equal to the operator's login must buy nothing."""
    app_mode(audit_ids=OWNER_ID)
    _sign_in(client, login=STRANGER, user_id=STRANGER_ID, display=OWNER)

    with patch.object(access, "installed_repositories", return_value=_installed()), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    assert resp.status_code == 200
    assert OWNER in resp.text            # shown, as the display name
    assert 'action="' + AUDIT_URL + '"' not in resp.text, (
        "a display name matching the operator's login drew an audit button"
    )


# --- CSRF still guards the audit POST ------------------------------------


async def test_csrf_still_refuses_a_cross_site_post(client, pool, app_mode, repo_is_public):
    app_mode(audit_ids=OWNER_ID)
    _sign_in(client)
    client.get("/dashboard")
    token = client.cookies[csrf.COOKIE_NAME]

    with patch.object(access, "installed_repositories", return_value=_installed()), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.post(AUDIT_URL, data={"csrf_token": token},
                           headers={"Origin": "https://evil.example"},
                           follow_redirects=False)

    assert resp.status_code == 403
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT count(*) AS n FROM audits")
        assert (await cur.fetchone())["n"] == 0


async def test_the_legitimate_audit_post_works_in_app_mode(
    client, pool, app_mode, repo_is_public,
):
    """The control has to let the real thing through, or the switch is an
    outage. This is also the operator allow-list matching a numeric id
    carried by the session cookie rather than by a claims blob."""
    app_mode(audit_ids=OWNER_ID)
    _sign_in(client)
    client.get("/dashboard")
    token = client.cookies[csrf.COOKIE_NAME]

    with patch.object(access, "installed_repositories", return_value=_installed()), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.post(AUDIT_URL, data={"csrf_token": token},
                           headers={"Origin": OURS}, follow_redirects=False)

    assert resp.status_code == 303, resp.text
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT requested_by FROM audits")
        assert (await cur.fetchone())["requested_by"] == OWNER


# --- security headers, and the CSP vs the GitHub redirect ----------------


def test_the_security_headers_are_unchanged_in_app_mode(client, app_mode):
    app_mode()
    _sign_in(client)
    with patch.object(access, "installed_repositories", return_value=[]), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    csp = resp.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "same-origin"


def test_the_csp_does_not_block_the_sign_in_navigation(client, app_mode):
    """Sign-in is a top-level navigation from an <a href> to github.com.

    No directive we set restricts that: form-action governs form submissions,
    connect-src governs fetch/XHR, and `navigate-to` -- the one directive that
    WOULD have applied -- is not in the policy and is not implemented by
    browsers anyway. Asserted rather than reasoned about, because adding
    navigate-to later would silently break sign-in.
    """
    app_mode()
    with patch.object(access, "installed_repositories", return_value=[]), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    csp = resp.headers["content-security-policy"]
    assert "navigate-to" not in csp
    # And the link really is a link, not a form that form-action would govern.
    assert 'href="/auth/login' in resp.text
    assert 'action="/auth/login' not in resp.text


def test_the_nav_points_at_the_app_flow_not_easyauth(client, app_mode):
    """The templates used to hardcode /.auth/*. A dashboard whose sign-in
    button points at a flow that no longer exists is indistinguishable from
    one that is down."""
    app_mode()
    with patch.object(access, "installed_repositories", return_value=[]), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    assert "/auth/login" in resp.text
    assert "/.auth/login/github" not in resp.text


# --- per-viewer access --------------------------------------------------


def test_anonymous_still_sees_nothing(client, app_mode):
    app_mode()
    client.cookies.clear()
    resp = client.get("/dashboard/repos")

    assert resp.status_code == 200
    assert "Sign in to continue" in resp.text
    assert PUBLIC not in resp.text


async def test_another_persons_audit_is_still_404(client, pool, app_mode):
    app_mode()
    _sign_in(client, login=STRANGER, user_id=STRANGER_ID)
    audit = await audits_mod.request_audit(
        pool, owner=OWNER, repo=PUBLIC, requested_by=OWNER, private=False,
    )
    await audits_mod.finish_audit(pool, audit["id"], status="done",
                                  report_markdown="# SECRET-REPORT")

    with patch.object(access, "_is_collaborator", return_value=True):
        page = client.get(f"/dashboard/audits/{audit['id']}")
        poll = client.get(f"/dashboard/audits/{audit['id']}.json")

    assert page.status_code == 404
    assert poll.status_code == 404
    assert "SECRET-REPORT" not in page.text


# --- the machine endpoints stay outside sign-in -------------------------


@pytest.mark.parametrize("path", ["/health", "/ready"])
def test_the_probes_need_no_session(client, app_mode, path):
    app_mode()
    client.cookies.clear()
    assert client.get(path).status_code == 200


def test_metrics_needs_no_session(client, app_mode):
    """Guarded by a bearer token, never by sign-in: Prometheus cannot follow
    a login redirect."""
    app_mode()
    client.cookies.clear()
    assert client.get("/metrics").status_code in (200, 401)


def test_the_webhook_needs_no_session(client, app_mode):
    """GitHub does not sign in. It must still reach our signature check
    rather than an auth gate — 401 invalid signature is OUR code answering."""
    app_mode()
    client.cookies.clear()
    resp = client.post("/webhook", content=b"{}", headers={"X-GitHub-Event": "ping"})

    assert resp.status_code == 401
    assert "signature" in resp.text.lower()
