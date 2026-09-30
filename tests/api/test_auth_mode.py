"""The sign-in mode switch, and what each mode reads identity from.

WHY A SWITCH AND NOT A REPLACEMENT. This is the one subsystem where a
mistake locks everybody out, including whoever would fix it. A setting means
rollback is one environment variable — no image rebuild, no Azure auth-config
edit, no waiting on a CI build while nobody can sign in.

It defaults to "easyauth", the mode that has been deployed and verified, so
the new path is opt-in rather than something a deploy switches on by
surprise.

THE PROPERTY THAT MATTERS MOST: the two modes must not be readable at the
same time. In "app" mode the EasyAuth header has to be IGNORED even when
present, because after the migration Azure's stripping is gone and that
header becomes attacker-controlled like any other. A viewer assembled from
whichever source happened to answer first would be exactly the
display-name-versus-login bug again, in a new costume.
"""

from __future__ import annotations

import base64
import json

from fastapi import Request

from codeguard.api import session
from codeguard.api.auth import client_viewer
from codeguard.config import Settings

SECRET = "a-test-session-secret-long-enough-to-pass"

OWNER_LOGIN = "ashrithaumd"
OWNER_ID = "183667058"
OTHER_LOGIN = "AshrithaPola"
OTHER_ID = "60956648"

_LOGIN_CLAIM = "urn:github:login"
_ID_CLAIM = "urn:github:id"


def _easyauth_blob(login, user_id):
    payload = {"auth_typ": "github", "claims": [
        {"typ": _LOGIN_CLAIM, "val": login},
        {"typ": _ID_CLAIM, "val": user_id},
    ]}
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _request(headers=None, cookies=None):
    hdrs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    if cookies:
        jar = "; ".join(f"{k}={v}" for k, v in cookies.items())
        hdrs.append((b"cookie", jar.encode()))
    return Request({
        "type": "http", "method": "GET", "path": "/dashboard/repos",
        "headers": hdrs, "query_string": b"", "scheme": "https",
        "server": ("test", 443),
    })


def _settings(**over):
    base = {
        "dashboard_dev_principal": "", "dashboard_trust_dev_principal": False,
        "dashboard_audit_principals": "", "session_secret": SECRET,
    }
    base.update(over)
    return Settings(**base)


def _with(monkeypatch, settings):
    monkeypatch.setattr("codeguard.api.auth.get_settings", lambda: settings)


def test_the_default_mode_is_the_deployed_one():
    """Opt-in, so no deploy flips sign-in by surprise."""
    assert _settings().dashboard_auth_mode == "easyauth"


def test_easyauth_mode_reads_the_header(monkeypatch):
    _with(monkeypatch, _settings(dashboard_auth_mode="easyauth"))
    viewer = client_viewer(_request(
        headers={"X-MS-CLIENT-PRINCIPAL": _easyauth_blob(OWNER_LOGIN, OWNER_ID)},
    ))

    assert viewer.login == OWNER_LOGIN
    assert viewer.user_id == OWNER_ID


def test_easyauth_mode_ignores_a_session_cookie(monkeypatch):
    """The reverse of the important property. While EasyAuth is in front, a
    cookie somebody minted must not be an alternative way in."""
    _with(monkeypatch, _settings(dashboard_auth_mode="easyauth"))
    value = session.issue(login=OWNER_LOGIN, user_id=OWNER_ID,
                          display_name=OWNER_LOGIN, secret=SECRET)

    assert client_viewer(_request(cookies={session.COOKIE_NAME: value})) is None


def test_app_mode_reads_the_signed_cookie(monkeypatch):
    _with(monkeypatch, _settings(dashboard_auth_mode="app"))
    value = session.issue(login=OWNER_LOGIN, user_id=OWNER_ID,
                          display_name="Ashritha Pola", secret=SECRET)
    viewer = client_viewer(_request(cookies={session.COOKIE_NAME: value}))

    assert viewer.login == OWNER_LOGIN
    assert viewer.user_id == OWNER_ID
    assert viewer.display_name == "Ashritha Pola"


def test_app_mode_IGNORES_the_easyauth_header(monkeypatch):
    """THE test this file exists for.

    Once sign-in is ours, Azure no longer strips X-MS-CLIENT-PRINCIPAL, so it
    is attacker-controlled like any other header. Accepting it in app mode
    would mean anyone could present any identity — the forged-blob attack
    that is currently impossible only because the platform blocks it.
    """
    _with(monkeypatch, _settings(dashboard_auth_mode="app"))
    request = _request(
        headers={"X-MS-CLIENT-PRINCIPAL": _easyauth_blob(OWNER_LOGIN, OWNER_ID)},
    )

    assert client_viewer(request) is None


def test_app_mode_prefers_neither_when_both_are_present(monkeypatch):
    """A forged header alongside a genuine cookie must not upgrade anyone:
    the cookie decides, and it says who it says."""
    _with(monkeypatch, _settings(dashboard_auth_mode="app"))
    value = session.issue(login=OTHER_LOGIN, user_id=OTHER_ID,
                          display_name=OTHER_LOGIN, secret=SECRET)
    viewer = client_viewer(_request(
        headers={"X-MS-CLIENT-PRINCIPAL": _easyauth_blob(OWNER_LOGIN, OWNER_ID)},
        cookies={session.COOKIE_NAME: value},
    ))

    assert viewer.login == OTHER_LOGIN
    assert viewer.user_id == OTHER_ID


def test_app_mode_with_no_secret_signs_everyone_out(monkeypatch):
    """Fail closed on a missing secret, rather than trusting an unverifiable
    cookie."""
    _with(monkeypatch, _settings(dashboard_auth_mode="app", session_secret=""))
    value = session.issue(login=OWNER_LOGIN, user_id=OWNER_ID,
                          display_name=OWNER_LOGIN, secret=SECRET)

    assert client_viewer(_request(cookies={session.COOKIE_NAME: value})) is None


def test_an_unknown_mode_fails_closed(monkeypatch):
    """A typo in the env var must not mean "trust everything". Nobody is
    signed in, which is noisy and safe rather than quiet and dangerous."""
    _with(monkeypatch, _settings(dashboard_auth_mode="eazyauth"))
    value = session.issue(login=OWNER_LOGIN, user_id=OWNER_ID,
                          display_name=OWNER_LOGIN, secret=SECRET)

    assert client_viewer(_request(
        headers={"X-MS-CLIENT-PRINCIPAL": _easyauth_blob(OWNER_LOGIN, OWNER_ID)},
        cookies={session.COOKIE_NAME: value},
    )) is None


def test_the_dev_override_still_wins_in_both_modes(monkeypatch):
    """Unchanged behaviour, and still two-key. Local uvicorn injects neither
    a header nor a cookie."""
    for mode in ("easyauth", "app"):
        _with(monkeypatch, _settings(
            dashboard_auth_mode=mode,
            dashboard_dev_principal=OWNER_LOGIN,
            dashboard_dev_principal_id=OWNER_ID,
            dashboard_trust_dev_principal=True,
        ))
        viewer = client_viewer(_request())
        assert viewer.login == OWNER_LOGIN, mode
        assert viewer.user_id == OWNER_ID, mode
