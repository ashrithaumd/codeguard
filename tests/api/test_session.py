"""The signed session cookie that replaces EasyAuth's injected header.

WHAT THIS REPLACES, AND WHY IT IS THE RISKIEST PART OF THE CHANGE.

Today identity is trusted because Azure's ingress STRIPS
`X-MS-CLIENT-PRINCIPAL` from any request that arrives carrying one — proved
live, not assumed: a forged blob produced no `undecodable` log line, so it
never reached the app at all. That property is Azure's, not ours.

Moving sign-in into the app means WE become responsible for it. There is no
stripping any more; instead every request carries a cookie the client can
edit freely, and the only thing standing between a visitor and any identity
they fancy is this HMAC. So this file is the direct replacement for
tests/api/test_identity.py's forged-blob tests, and it has to be at least as
suspicious as the thing it replaces.

THE DESIGN, stated so the tests can be read against it:

    cg_session = v1.<payload>.<signature>

    payload    base64url(compact JSON) — {"l": login, "i": user_id,
               "n": display_name, "e": expiry as a unix timestamp}
    signature  base64url(HMAC-SHA256(secret, "v1.<payload>"))

  * THE VERSION IS SIGNED, not just prefixed. A future format change can
    then invalidate old cookies instead of risking a v2 verifier
    mis-reading a v1 payload as something it is not.
  * EXPIRY IS INSIDE THE SIGNED PAYLOAD. A cookie's own Max-Age is a hint
    to the browser and nothing more — the client can keep sending an
    "expired" cookie forever, so the authoritative deadline has to be
    covered by the signature.
  * THE GITHUB TOKEN IS NEVER IN IT. The user-to-server token lives
    server-side, keyed by user id. A token in a cookie is a token in every
    proxy log and every browser profile backup.
  * NO SECRET, NO SESSIONS. With SESSION_SECRET unset, issuing and
    verifying both refuse. Every other default in this codebase fails
    closed and an authentication secret is the last place to make an
    exception.

WHAT THIS DESIGN DOES NOT GIVE US, recorded rather than glossed: sign-out
clears the cookie but cannot invalidate a COPY of it. Anyone who already
extracted the value keeps a working session until `e` passes. Real
revocation needs server-side session state, which is a bigger change than
this one; the mitigation is a short fixed lifetime.
"""

from __future__ import annotations

import base64
import json
import time

import pytest

from codeguard.api import session

SECRET = "test-session-secret-not-a-real-one"
OTHER_SECRET = "a-different-secret-entirely-and-long-enough"

LOGIN = "ashrithaumd"
USER_ID = "183667058"
DISPLAY = "Ashritha Pola"


def _issue(secret=SECRET, **over):
    kwargs = {"login": LOGIN, "user_id": USER_ID, "display_name": DISPLAY}
    kwargs.update(over)
    return session.issue(secret=secret, **kwargs)


# --- the round trip -----------------------------------------------------


def test_a_session_round_trips():
    value = _issue()
    viewer = session.verify(value, secret=SECRET)

    assert viewer is not None
    assert viewer.login == LOGIN
    assert viewer.user_id == USER_ID
    assert viewer.display_name == DISPLAY


def test_the_cookie_is_opaque_but_not_secret_bearing():
    """It is signed, not encrypted, so the login is readable by design —
    that is fine, it is the user's own public username. What must NEVER be
    in there is anything that grants access on its own."""
    value = _issue()

    assert SECRET not in value
    # The payload decodes to exactly the four declared fields and nothing
    # else, so a token or a scope cannot be smuggled in by a later change
    # without this failing.
    payload = json.loads(base64.urlsafe_b64decode(value.split(".")[1] + "=="))
    assert set(payload) == {"l", "i", "n", "e"}


# --- the forgeries: the direct replacement for the stripped-header test --


def test_a_tampered_payload_is_rejected():
    """The whole point. Swap the login for the operator's and the signature
    no longer matches."""
    version, payload, sig = _issue(login="AshrithaPola", user_id="60956648").split(".")
    forged_payload = base64.urlsafe_b64encode(
        json.dumps({"l": LOGIN, "i": USER_ID, "n": DISPLAY,
                    "e": int(time.time()) + 3600}).encode()
    ).decode().rstrip("=")

    assert session.verify(f"{version}.{forged_payload}.{sig}", secret=SECRET) is None


def test_a_tampered_signature_is_rejected():
    version, payload, sig = _issue().split(".")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]

    assert session.verify(f"{version}.{payload}.{flipped}", secret=SECRET) is None


def test_an_unsigned_cookie_is_rejected():
    """A payload with no signature at all, which is what someone writes
    first when they try this by hand."""
    payload = base64.urlsafe_b64encode(
        json.dumps({"l": LOGIN, "i": USER_ID, "n": DISPLAY,
                    "e": int(time.time()) + 3600}).encode()
    ).decode().rstrip("=")

    assert session.verify(f"v1.{payload}.", secret=SECRET) is None
    assert session.verify(f"v1.{payload}", secret=SECRET) is None
    assert session.verify(payload, secret=SECRET) is None


def test_a_cookie_signed_with_another_secret_is_rejected():
    """Which is also the rotation story: changing SESSION_SECRET signs
    everyone out rather than letting old cookies through."""
    assert session.verify(_issue(secret=OTHER_SECRET), secret=SECRET) is None


def test_an_expired_cookie_is_rejected():
    value = _issue(ttl_seconds=-1)
    assert session.verify(value, secret=SECRET) is None


def test_expiry_is_covered_by_the_signature():
    """A client can send a cookie forever regardless of Max-Age, so moving
    the deadline must break the signature rather than extend the session."""
    version, payload, sig = _issue(ttl_seconds=-1).split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=="))
    decoded["e"] = int(time.time()) + 86400
    extended = base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode().rstrip("=")

    assert session.verify(f"{version}.{extended}.{sig}", secret=SECRET) is None


def test_a_version_change_invalidates_old_cookies():
    """The version is inside the signed material, so a v1 cookie cannot be
    replayed as v2 by editing the prefix."""
    version, payload, sig = _issue().split(".")
    assert session.verify(f"v2.{payload}.{sig}", secret=SECRET) is None


@pytest.mark.parametrize("junk", [
    "", "   ", "not-a-cookie", "v1", "v1.", "v1..", "a.b.c.d",
    "v1.!!!not-base64!!!.sig", "v1." + base64.urlsafe_b64encode(b"not json").decode() + ".sig",
])
def test_garbage_is_rejected_without_raising(junk):
    """Every one of these arrives eventually, from a scanner or a stale
    cookie, and a 500 on the identity path would be an outage."""
    assert session.verify(junk, secret=SECRET) is None


def test_a_payload_missing_its_login_is_rejected():
    """Correctly signed but incomplete. Fail closed rather than construct a
    viewer with an empty login, because an empty login compared against an
    allow-list or a collaborator check is a question nobody meant to ask."""
    for payload in ({"i": USER_ID, "e": int(time.time()) + 60},
                    {"l": "", "i": USER_ID, "e": int(time.time()) + 60},
                    {"l": LOGIN, "i": USER_ID}):
        value = session._sign(payload, secret=SECRET)
        assert session.verify(value, secret=SECRET) is None, payload


# --- failing closed on configuration -----------------------------------


def test_no_secret_means_no_sessions():
    """Issuing and verifying both refuse. An authentication secret is the
    last place to accept a permissive default."""
    with pytest.raises(session.SessionSecretMissing):
        _issue(secret="")
    assert session.verify(_issue(), secret="") is None


def test_a_short_secret_is_refused():
    """A two-character secret is not a secret, and the failure mode is
    silent: everything works until somebody guesses it."""
    with pytest.raises(session.SessionSecretMissing):
        _issue(secret="abc")


# --- the display name keeps its single job ------------------------------


def test_the_display_name_is_carried_but_is_not_identity():
    """It rides along for the nav, as it does today. What must not happen is
    a viewer whose LOGIN comes from it."""
    value = _issue(display_name=LOGIN, login="AshrithaPola", user_id="60956648")
    viewer = session.verify(value, secret=SECRET)

    assert viewer.display_name == LOGIN     # what it says
    assert viewer.login == "AshrithaPola"   # who they are
    assert viewer.user_id == "60956648"
