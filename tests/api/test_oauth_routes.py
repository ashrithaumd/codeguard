"""The app's own GitHub OAuth flow: /auth/login, /auth/callback, /auth/logout.

WHAT THIS BUYS, and why EasyAuth could not:

  * prompt=select_account, so GitHub shows its account picker every time.
    EasyAuth cannot — measured: it drops unknown query parameters from the
    authorize URL and exposes no loginParameters for the GitHub provider.
    The cost of that gap was a real misdiagnosis: a silent sign-in as the
    wrong account looked exactly like a broken session.
  * A sign-out that actually ends the session we control.
  * A user-to-server token, which phase 2 needs to list a visitor's own
    repositories. It is stored server-side and never reaches the browser.

THE THREE WAYS THIS SHAPE OF FLOW IS NORMALLY GOT WRONG, each with a test:

  1. NO STATE CHECK. Without it, an attacker completes their own
     authorization and feeds the resulting code to a victim's browser,
     logging the victim into the ATTACKER's account — where the victim may
     then connect their own repositories. The state cookie must be present,
     match, and be single-use.
  2. AN OPEN REDIRECT in `next`. `/auth/login?next=https://evil.example`
     turns our sign-in into a credential-phishing stepping stone that
     genuinely starts on our domain. Only local paths are accepted.
  3. THE TOKEN LEAKING. It must appear in no cookie, no response body and
     no redirect URL — a token in a URL is a token in browser history, in
     the Referer header, and in every proxy log along the way.
"""

from __future__ import annotations

from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import pytest

from codeguard.api import oauth, session
from codeguard.config import Settings, get_settings

SECRET = "a-test-session-secret-long-enough-to-pass"
CLIENT_ID = "Iv23liMt21lUXpodO0tx"
CLIENT_SECRET = "test-client-secret-value"

LOGIN = "ashrithaumd"
USER_ID = 183667058
DISPLAY = "Ashritha Pola"
TOKEN = "ghu_aTestUserToServerTokenValue"


@pytest.fixture
def app_mode(monkeypatch):
    """Switch the running app into "app" auth mode."""
    base = get_settings().model_dump()
    base.update({
        "dashboard_auth_mode": "app",
        "github_oauth_client_id": CLIENT_ID,
        "github_oauth_client_secret": CLIENT_SECRET,
        "session_secret": SECRET,
        "dashboard_dev_principal": "", "dashboard_trust_dev_principal": False,
    })
    patched = Settings(**base)
    for target in ("codeguard.api.auth.get_settings",
                   "codeguard.api.oauth.get_settings",
                   "codeguard.api.routes.dashboard.get_settings"):
        monkeypatch.setattr(target, lambda: patched)
    return patched


@pytest.fixture
def github_accepts(monkeypatch):
    """GitHub exchanges the code and identifies the user.

    Patched at oauth's own two seams rather than at `requests`, so the test
    says which call it is standing in for.
    """
    calls = {}

    def _exchange(code, **kw):
        calls["code"] = code
        return TOKEN

    def _identify(token):
        calls["token"] = token
        return {"login": LOGIN, "id": USER_ID, "name": DISPLAY}

    monkeypatch.setattr(oauth, "_exchange_code_for_token", _exchange)
    monkeypatch.setattr(oauth, "_fetch_github_user", _identify)
    return calls


def _start_login(client, next_path="/dashboard/repos"):
    resp = client.get(f"/auth/login?next={next_path}", follow_redirects=False)
    location = resp.headers.get("location", "")
    state = parse_qs(urlsplit(location).query).get("state", [""])[0]
    return resp, location, state


# --- /auth/login ---------------------------------------------------------


def test_login_redirects_to_github_with_the_account_picker(client, app_mode):
    """The reason this whole change exists."""
    resp, location, state = _start_login(client)
    query = parse_qs(urlsplit(location).query)

    assert resp.status_code in (302, 303, 307)
    assert urlsplit(location).netloc == "github.com"
    assert query["prompt"] == ["select_account"]
    assert query["client_id"] == [CLIENT_ID]
    assert state, "no state parameter"
    assert "/auth/callback" in query["redirect_uri"][0]


def test_login_sets_a_state_cookie_that_is_not_readable_by_script(client, app_mode):
    resp, _location, state = _start_login(client)
    header = resp.headers["set-cookie"]

    assert oauth.STATE_COOKIE in header
    assert "httponly" in header.lower()
    assert "samesite=lax" in header.lower(), (
        "Strict would not survive the redirect back from github.com"
    )


def test_login_refuses_when_no_client_secret_is_configured(client, monkeypatch):
    """Fail closed rather than bounce the user to GitHub for a flow that
    cannot possibly complete."""
    base = get_settings().model_dump()
    base.update({"dashboard_auth_mode": "app", "github_oauth_client_id": CLIENT_ID,
                 "github_oauth_client_secret": "", "session_secret": SECRET})
    patched = Settings(**base)
    monkeypatch.setattr("codeguard.api.oauth.get_settings", lambda: patched)

    resp = client.get("/auth/login", follow_redirects=False)
    assert resp.status_code >= 400
    assert "github.com" not in resp.headers.get("location", "")


# --- the open redirect ---------------------------------------------------


@pytest.mark.parametrize("hostile", [
    "https://evil.example/", "//evil.example/", "http://evil.example",
    "javascript:alert(1)", "/\\evil.example", "https:/evil.example",
])
def test_a_hostile_next_is_not_honoured(client, app_mode, github_accepts, hostile):
    """Our sign-in must not become a redirector. The attack is convincing
    precisely because the link genuinely starts on our domain."""
    _resp, _location, state = _start_login(client, next_path=hostile)

    done = client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
    target = done.headers.get("location", "")

    assert "evil.example" not in target, target
    assert not target.startswith("javascript:")
    assert target.startswith("/"), target


def test_a_local_next_is_honoured(client, app_mode, github_accepts):
    _resp, _location, state = _start_login(client, next_path="/dashboard?repo=x")
    done = client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

    assert done.headers["location"].startswith("/dashboard")


# --- /auth/callback: the state check ------------------------------------


def test_the_callback_refuses_a_missing_state(client, app_mode, github_accepts):
    _start_login(client)
    resp = client.get("/auth/callback?code=abc", follow_redirects=False)

    assert resp.status_code >= 400
    assert session.COOKIE_NAME not in resp.cookies


def test_the_callback_refuses_a_state_that_does_not_match(client, app_mode, github_accepts):
    """The CSRF-on-login attack: the attacker's code plus their own state,
    delivered to the victim's browser, which holds a different cookie."""
    _start_login(client)
    resp = client.get("/auth/callback?code=abc&state=not-the-one", follow_redirects=False)

    assert resp.status_code >= 400
    assert session.COOKIE_NAME not in resp.cookies


def test_the_callback_refuses_when_the_state_cookie_is_absent(client, app_mode, github_accepts):
    """Half of a double-submit is not a submit. compare_digest("","") is
    True, so "nothing to compare" must not read as "nothing to object to"."""
    _resp, _location, state = _start_login(client)
    client.cookies.clear()

    resp = client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
    assert resp.status_code >= 400


def test_the_state_is_single_use(client, app_mode, github_accepts):
    """A replayed callback must not mint a second session."""
    _resp, _location, state = _start_login(client)
    first = client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
    second = client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

    assert first.status_code in (302, 303, 307)
    assert second.status_code >= 400


def test_the_callback_refuses_with_no_code(client, app_mode, github_accepts):
    _resp, _location, state = _start_login(client)
    resp = client.get(f"/auth/callback?state={state}", follow_redirects=False)
    assert resp.status_code >= 400


# --- /auth/callback: the happy path and the session it mints -------------


def test_a_successful_callback_signs_the_user_in(client, app_mode, github_accepts):
    _resp, _location, state = _start_login(client)
    resp = client.get(f"/auth/callback?code=the-code&state={state}",
                      follow_redirects=False)

    assert resp.status_code in (302, 303, 307)
    assert github_accepts["code"] == "the-code"
    value = resp.cookies[session.COOKIE_NAME]
    viewer = session.verify(value, secret=SECRET)
    assert viewer.login == LOGIN
    assert viewer.user_id == str(USER_ID)
    assert viewer.display_name == DISPLAY


def test_the_session_cookie_has_the_right_flags(client, app_mode, github_accepts):
    _resp, _location, state = _start_login(client)
    resp = client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
    header = [h for h in resp.headers.get_list("set-cookie")
              if h.startswith(session.COOKIE_NAME)][0]

    assert "httponly" in header.lower()
    assert "samesite=lax" in header.lower(), (
        "Strict would break the landing navigation back from github.com"
    )
    assert "path=/" in header.lower()


# --- the token must not leak --------------------------------------------


def test_the_token_appears_in_nothing_the_browser_receives(
    client, app_mode, github_accepts,
):
    """No cookie, no body, no redirect URL. A token in a URL is a token in
    browser history, in Referer, and in every proxy log on the way."""
    _resp, _location, state = _start_login(client)
    resp = client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

    assert TOKEN not in resp.text
    assert TOKEN not in resp.headers.get("location", "")
    for header in resp.headers.get_list("set-cookie"):
        assert TOKEN not in header
    assert TOKEN not in str(dict(resp.cookies))


# --- /auth/logout -------------------------------------------------------


def test_logout_clears_the_session(client, app_mode, github_accepts):
    _resp, _location, state = _start_login(client)
    client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
    assert client.cookies.get(session.COOKIE_NAME)

    resp = client.post("/auth/logout", follow_redirects=False)

    assert resp.status_code in (302, 303, 307)
    cleared = [h for h in resp.headers.get_list("set-cookie")
               if h.startswith(session.COOKIE_NAME)]
    assert cleared, "the session cookie was not cleared"
    assert 'cg_session=""' in cleared[0] or "cg_session=;" in cleared[0] or \
        "max-age=0" in cleared[0].lower() or "expires=thu, 01 jan 1970" in cleared[0].lower()


def test_logout_is_not_a_get(client, app_mode):
    """A GET logout is forgeable: any page could sign a visitor out by
    embedding an image. Minor, but free to avoid."""
    assert client.get("/auth/logout", follow_redirects=False).status_code in (404, 405)


# --- the token is used once and kept nowhere ----------------------------


async def test_the_token_is_written_to_no_database_column(
    client, pool, app_mode, github_accepts,
):
    """It identifies the signer and is then discarded.

    An earlier draft stored it for phase 2. Storing a credential before
    anything reads it is a liability with no benefit -- it would need
    encryption-at-rest reasoning, refresh handling and a deletion policy, to
    serve a feature that does not exist. Phase 2 designs that with a live
    consumer to design against.

    Searches EVERY text-ish column of EVERY table rather than naming one, so
    this keeps holding when a later change adds a table that looks like a
    convenient place to put it.
    """
    _resp, _location, state = _start_login(client)
    client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

    async with pool.connection() as conn:
        cur = await conn.execute(
            """
            SELECT table_name, column_name FROM information_schema.columns
            WHERE table_schema = 'public'
              AND data_type IN ('text', 'character varying', 'json', 'jsonb')
            """
        )
        columns = [(r["table_name"], r["column_name"]) for r in await cur.fetchall()]
        assert columns, "no columns inspected -- the search proved nothing"

        found = []
        for table, column in columns:
            cur = await conn.execute(
                f'SELECT count(*) AS n FROM "{table}" WHERE "{column}"::text LIKE %s',
                (f"%{TOKEN}%",),
            )
            if (await cur.fetchone())["n"]:
                found.append(f"{table}.{column}")

    assert found == [], f"the GitHub token was written to {found}"


async def test_no_token_table_exists(pool):
    """The table itself is gone, not merely unused."""
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT to_regclass('public.github_user_tokens') AS t"
        )
        assert (await cur.fetchone())["t"] is None


async def test_sign_in_still_works_without_any_token_storage(
    client, app_mode, github_accepts,
):
    """The precision guard: removing storage must not remove sign-in."""
    _resp, _location, state = _start_login(client)
    resp = client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)

    assert resp.status_code in (302, 303, 307)
    viewer = session.verify(resp.cookies[session.COOKIE_NAME], secret=SECRET)
    assert viewer.login == LOGIN
