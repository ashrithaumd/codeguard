"""Identity is the GitHub login, never the display name.

THE DEFECT THIS REPRODUCES
--------------------------
`client_principal` read `X-MS-CLIENT-PRINCIPAL-NAME`, which EasyAuth builds
from the `claims/name` claim — the GitHub **display name**. Measured on the
deployed build:

    name_typ = http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
                                         is_display = TRUE
    urn:github:login   present, carries the signed-in session's login
    urn:github:id      present, carries the numeric id

So every access decision asked GitHub about a collaborator whose name is
"Ashritha Pola", which is not a username. Production: 11 repositories
installed, 11 fetched, **0 rendered**, for everyone including the owner.
`_is_collaborator(…, 'ashrithaumd')` true; `_is_collaborator(…, 'Ashritha
Pola')` false.

WHY THIS IS A SECURITY BUG AND NOT ONLY AN OUTAGE. A GitHub display name is
free text, mutable, and **not unique**. This is not a uniqueness argument —
the collision already exists in the accounts this deployment is tested with:

    ashrithaumd   183667058   Ashritha Pola
    AshrithaPola   60956648   Ashritha Pola

Two different people, one identity string. It failed CLOSED — the allow-list
held a login, so neither matched and nobody could audit — and the tempting
repair was to put the display name in the allow-list, which would have
handed operator rights, and the Anthropic bill, to whoever else happened to
share it. The fix has to move identity to the login, not make the display
name work.

WHY THE ALLOW-LIST USES THE NUMERIC ID AND NOT THE LOGIN. Repo access must
use the login, because GitHub's collaborator endpoint is keyed on username —
and that path is self-correcting, since after a rename EasyAuth reports the
new login and GitHub answers for the new login. The allow-list is the only
place a name is STORED, so it is the only place a rename matters: a released
login can be registered by someone else, who would inherit the audit button.
Ids are immutable, so that is where they belong.
"""

from __future__ import annotations

import base64
import json

import pytest
from fastapi import Request

from codeguard.api.auth import client_principal, client_viewer
from codeguard.config import Settings

# The two real accounts, because inventing values would have hidden the
# collision that made this worth fixing.
OWNER_LOGIN = "ashrithaumd"
OWNER_ID = "183667058"
OTHER_LOGIN = "AshrithaPola"
OTHER_ID = "60956648"
SHARED_DISPLAY_NAME = "Ashritha Pola"

_LOGIN_CLAIM = "urn:github:login"
_ID_CLAIM = "urn:github:id"
_NAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"


def _blob(*, login=None, user_id=None, display=None, extra=()):
    """An X-MS-CLIENT-PRINCIPAL header in the shape EasyAuth actually sends,
    confirmed against production rather than guessed."""
    claims = []
    if login is not None:
        claims.append({"typ": _LOGIN_CLAIM, "val": login})
    if user_id is not None:
        claims.append({"typ": _ID_CLAIM, "val": user_id})
    if display is not None:
        claims.append({"typ": _NAME_CLAIM, "val": display})
    claims.extend(extra)
    payload = {"auth_typ": "github", "name_typ": _NAME_CLAIM, "claims": claims}
    return base64.b64encode(json.dumps(payload).encode()).decode()


def _request(headers: dict[str, str]) -> Request:
    return Request({
        "type": "http", "method": "GET", "path": "/dashboard/repos",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "query_string": b"", "scheme": "https", "server": ("test", 443),
    })


def _settings(**over):
    base = {
        "dashboard_dev_principal": "", "dashboard_trust_dev_principal": False,
        "dashboard_audit_principals": "",
    }
    base.update(over)
    return Settings(**base)


@pytest.fixture(autouse=True)
def _no_dev_override(monkeypatch):
    """The dev override must not decide any of these. Patched to an explicit
    off state rather than trusted to be off, because a stray .env value would
    otherwise make every test below pass for the wrong reason."""
    monkeypatch.setattr("codeguard.api.auth.get_settings", lambda: _settings())


# --- the regression ------------------------------------------------------


def test_the_principal_is_the_login_not_the_display_name():
    request = _request({
        "X-MS-CLIENT-PRINCIPAL": _blob(
            login=OWNER_LOGIN, user_id=OWNER_ID, display=SHARED_DISPLAY_NAME,
        ),
        "X-MS-CLIENT-PRINCIPAL-NAME": SHARED_DISPLAY_NAME,
    })

    assert client_principal(request) == OWNER_LOGIN


def test_a_display_name_matching_the_operators_login_grants_nothing():
    """THE regression this file exists for.

    Someone sets their GitHub display name to the operator's login. The
    NAME header therefore reads "ashrithaumd" while the login claim says
    otherwise. They must get neither operator rights nor repo access.
    """
    request = _request({
        # The attacker's own login and id...
        "X-MS-CLIENT-PRINCIPAL": _blob(
            login=OTHER_LOGIN, user_id=OTHER_ID, display=OWNER_LOGIN,
        ),
        # ...and a display name chosen to impersonate the operator.
        "X-MS-CLIENT-PRINCIPAL-NAME": OWNER_LOGIN,
    })

    viewer = client_viewer(request)
    assert viewer is not None
    # Repo access: keyed on the login, so GitHub is asked about the
    # attacker, not the operator.
    assert client_principal(request) == OTHER_LOGIN
    assert client_principal(request) != OWNER_LOGIN
    # Operator rights: keyed on the id, which they cannot choose.
    allow = _settings(dashboard_audit_principals=OWNER_ID)
    assert allow.may_trigger_audit(viewer.user_id) is False
    # And the id they do carry is their own.
    assert viewer.user_id == OTHER_ID


def test_two_accounts_sharing_a_display_name_are_distinguishable():
    """The live collision. Before the fix these two were the same principal
    string; afterwards nothing about them is shared."""
    owner = client_viewer(_request({
        "X-MS-CLIENT-PRINCIPAL": _blob(
            login=OWNER_LOGIN, user_id=OWNER_ID, display=SHARED_DISPLAY_NAME),
    }))
    other = client_viewer(_request({
        "X-MS-CLIENT-PRINCIPAL": _blob(
            login=OTHER_LOGIN, user_id=OTHER_ID, display=SHARED_DISPLAY_NAME),
    }))

    assert owner.display_name == other.display_name  # the collision itself
    assert owner.login != other.login
    assert owner.user_id != other.user_id


# --- failing closed -----------------------------------------------------


def test_a_missing_login_claim_is_signed_out():
    """Never fall back to the display name. A blob without the login claim
    means we cannot say who this is, and "cannot say" must mean anonymous —
    not "use whatever other string is to hand"."""
    request = _request({
        "X-MS-CLIENT-PRINCIPAL": _blob(user_id=OWNER_ID, display=SHARED_DISPLAY_NAME),
        "X-MS-CLIENT-PRINCIPAL-NAME": SHARED_DISPLAY_NAME,
    })

    assert client_principal(request) is None
    assert client_viewer(request) is None


def test_a_missing_blob_is_signed_out_even_with_the_name_header():
    """The exact shape of the old bug: the NAME header alone must no longer
    be enough to be somebody."""
    request = _request({"X-MS-CLIENT-PRINCIPAL-NAME": SHARED_DISPLAY_NAME})

    assert client_principal(request) is None


def test_an_undecodable_blob_is_signed_out():
    for junk in ("not-base64!!", "", base64.b64encode(b"not json").decode()):
        assert client_principal(_request({"X-MS-CLIENT-PRINCIPAL": junk})) is None


def test_an_anonymous_request_is_signed_out():
    assert client_principal(_request({})) is None
    assert client_viewer(_request({})) is None


def test_a_blank_login_claim_is_signed_out():
    request = _request({"X-MS-CLIENT-PRINCIPAL": _blob(login="   ", user_id=OWNER_ID)})
    assert client_principal(request) is None


# --- the allow-list -----------------------------------------------------


def test_the_allow_list_matches_a_numeric_id():
    allow = _settings(dashboard_audit_principals=OWNER_ID)
    assert allow.may_trigger_audit(OWNER_ID) is True
    assert allow.may_trigger_audit(OTHER_ID) is False


def test_the_allow_list_refuses_a_login_entirely():
    """Ids only, with no login fallback. Accepting both forms would reopen
    the hole this closes: a released login re-registered by someone else
    would inherit the audit button."""
    allow = _settings(dashboard_audit_principals=OWNER_LOGIN)
    assert allow.may_trigger_audit(OWNER_ID) is False
    assert allow.may_trigger_audit(OWNER_LOGIN) is False


def test_a_non_numeric_allow_list_entry_is_ignored_not_matched():
    """A misconfigured entry must be inert, never a wildcard."""
    allow = _settings(dashboard_audit_principals=f"{OWNER_LOGIN}, {OWNER_ID}")
    assert allow.may_trigger_audit(OWNER_ID) is True
    assert allow.may_trigger_audit(OTHER_ID) is False
    assert allow.may_trigger_audit(OWNER_LOGIN) is False


def test_an_empty_allow_list_means_nobody():
    allow = _settings(dashboard_audit_principals="")
    assert allow.may_trigger_audit(OWNER_ID) is False
    assert allow.may_trigger_audit(None) is False
    assert allow.may_trigger_audit("") is False


def test_a_viewer_with_no_id_claim_cannot_be_an_operator():
    """A blob carrying a login but no id: usable for repo access, never for
    operator rights, because there is nothing immutable to match on."""
    request = _request({"X-MS-CLIENT-PRINCIPAL": _blob(login=OWNER_LOGIN)})
    viewer = client_viewer(request)

    assert viewer.login == OWNER_LOGIN
    assert viewer.user_id == ""
    assert _settings(dashboard_audit_principals=OWNER_ID).may_trigger_audit("") is False


# --- the display name keeps exactly one job -----------------------------


def test_the_display_name_is_still_available_for_the_nav():
    request = _request({
        "X-MS-CLIENT-PRINCIPAL": _blob(
            login=OWNER_LOGIN, user_id=OWNER_ID, display=SHARED_DISPLAY_NAME),
    })

    assert client_viewer(request).display_name == SHARED_DISPLAY_NAME


def test_the_display_name_falls_back_to_the_login_when_unset():
    """An account with no display name should show as something, and the
    login is the honest choice."""
    request = _request({"X-MS-CLIENT-PRINCIPAL": _blob(login=OWNER_LOGIN, user_id=OWNER_ID)})

    assert client_viewer(request).display_name == OWNER_LOGIN


# --- the dev override ---------------------------------------------------


def test_the_dev_override_still_works_and_needs_both_keys(monkeypatch):
    """Local uvicorn injects no headers. The two-key requirement is
    unchanged: a single setting would mean one forgotten env var accepts a
    forged identity."""
    patched = _settings(
        dashboard_dev_principal=OWNER_LOGIN,
        dashboard_trust_dev_principal=True,
        dashboard_dev_principal_id=OWNER_ID,
    )
    monkeypatch.setattr("codeguard.api.auth.get_settings", lambda: patched)

    viewer = client_viewer(_request({}))
    assert viewer.login == OWNER_LOGIN
    assert viewer.user_id == OWNER_ID


def test_the_dev_override_is_ignored_without_the_trust_flag(monkeypatch):
    patched = _settings(
        dashboard_dev_principal=OWNER_LOGIN, dashboard_trust_dev_principal=False,
    )
    monkeypatch.setattr("codeguard.api.auth.get_settings", lambda: patched)

    assert client_principal(_request({})) is None


def test_a_login_in_the_allow_list_is_reported_not_silently_dropped():
    """Dropping it is right; dropping it quietly is not.

    A misconfigured allow-list fails closed, so its only symptom is a button
    that is absent — which looks exactly like "not configured yet". The
    entries that were ignored have to be nameable at startup.
    """
    allow = _settings(dashboard_audit_principals=f"{OWNER_LOGIN}, {OWNER_ID}, bad-entry")

    assert allow.audit_principals == frozenset({OWNER_ID})
    assert set(allow.audit_principals_ignored) == {OWNER_LOGIN, "bad-entry"}


def test_a_correctly_configured_allow_list_reports_nothing_ignored():
    allow = _settings(dashboard_audit_principals=f"{OWNER_ID}, {OTHER_ID}")
    assert allow.audit_principals_ignored == ()
