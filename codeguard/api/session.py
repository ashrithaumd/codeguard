"""The signed session cookie, for when this app does its own sign-in.

WHAT THIS REPLACES, AND WHY IT IS THE RISKIEST PIECE OF THE CHANGE.

Under EasyAuth, identity is trustworthy because the Azure ingress STRIPS
`X-MS-CLIENT-PRINCIPAL` from any request that arrives carrying one. That was
verified live rather than assumed — a forged blob produced no "undecodable"
log line, so it never reached the application at all. The property belongs to
Azure, not to us.

Doing sign-in ourselves means inheriting that responsibility. Nothing strips
anything now: every request carries a cookie the client can edit at will, and
this HMAC is the only thing between a visitor and any identity they choose.
tests/api/test_session.py is the direct replacement for the forged-header
tests and is deliberately at least as suspicious.

FORMAT

    cg_session = v1.<payload>.<signature>

    payload    base64url(compact JSON) — {"l": login, "i": user_id,
               "n": display_name, "e": expiry as a unix timestamp}
    signature  base64url(HMAC-SHA256(secret, "v1.<payload>"))

Four decisions worth stating, because each one closes a specific hole:

  * THE VERSION IS SIGNED, not merely prefixed. A later format change can
    then invalidate old cookies rather than risk a v2 verifier reading a v1
    payload as something it never was.
  * EXPIRY LIVES INSIDE THE SIGNED PAYLOAD. A cookie's Max-Age is advice to
    the browser; a client can keep presenting an "expired" cookie forever.
    The authoritative deadline has to be covered by the signature.
  * THE GITHUB TOKEN IS NEVER IN HERE. The user-to-server token stays
    server-side, keyed by user id. A token in a cookie is a token in every
    proxy log and every browser-profile backup.
  * NO SECRET, NO SESSIONS. With the secret unset or trivially short,
    issuing raises and verifying returns None. Every other default in this
    codebase fails closed; an authentication secret is the last place to
    make an exception.

Signed, NOT encrypted, which is deliberate: the only thing inside is the
viewer's own public GitHub username, id and display name. Encryption would
add key management for no secret worth hiding, and would make debugging a
session problem require a decryption step.

WHAT THIS DESIGN DOES NOT PROVIDE, recorded rather than glossed over:
sign-out clears the cookie but cannot invalidate a COPY of it. Anyone who
already has the value keeps a working session until `e` passes. True
revocation needs server-side session state — a larger change than this — and
the mitigation meanwhile is a short fixed lifetime.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time

from codeguard.api.auth import Viewer

logger = logging.getLogger(__name__)

COOKIE_NAME = "cg_session"

_VERSION = "v1"

# 12 hours, matching the CSRF cookie's lifetime. Short because sign-out
# cannot revoke a copied cookie (see the module docstring), so the expiry is
# the only bound on a leaked one; long enough that a working session does not
# evaporate mid-task.
DEFAULT_TTL_SECONDS = 12 * 60 * 60

# Below this, a "secret" is a formality. 32 characters is what
# `python -c "import secrets; print(secrets.token_urlsafe(32))"` produces,
# which is what the deployment docs tell an operator to run.
MIN_SECRET_CHARS = 32


class SessionSecretMissing(RuntimeError):
    """Raised when asked to issue a session with no usable secret.

    An exception rather than a falsy return: a caller that forgets to check
    would otherwise hand out unsigned sessions, and the whole point of this
    module is that such a thing cannot exist.
    """


def _b64(raw: bytes) -> str:
    # Padding stripped: it carries no information and '=' in a cookie value
    # invites quoting bugs in whatever handles it next.
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _usable(secret: str) -> bool:
    return bool(secret) and len(secret) >= MIN_SECRET_CHARS


def _sign(payload: dict, *, secret: str) -> str:
    """Sign an arbitrary payload dict. Exposed for tests that need to build a
    correctly-signed but semantically wrong cookie — proving the SEMANTIC
    checks work needs a cookie whose signature is genuine."""
    if not _usable(secret):
        raise SessionSecretMissing(
            "SESSION_SECRET is unset or shorter than "
            f"{MIN_SECRET_CHARS} characters; refusing to issue a session"
        )
    # separators: compact, and stable — a payload whose bytes depend on
    # formatting would make the signature depend on it too.
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signed = f"{_VERSION}.{body}"
    mac = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).digest()
    return f"{signed}.{_b64(mac)}"


def issue(
    *, login: str, user_id: str, display_name: str, secret: str,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    """A signed session for this viewer. Raises if the secret is unusable."""
    return _sign(
        {
            "l": login,
            "i": user_id,
            "n": display_name,
            "e": int(time.time()) + ttl_seconds,
        },
        secret=secret,
    )


def verify(value: str | None, *, secret: str) -> Viewer | None:
    """The viewer this cookie attests to, or None.

    None for every failure, without raising, because all of these arrive in
    practice — a stale cookie after a secret rotation, a scanner sending
    junk, a truncated value from a proxy — and a 500 on the identity path
    would be an outage. The reasons are not distinguished to the caller
    either: "not signed in" is the only answer any of them should produce.
    """
    if not value or not _usable(secret):
        return None

    parts = value.split(".")
    if len(parts) != 3:
        return None
    version, body, presented = parts
    if version != _VERSION or not body or not presented:
        return None

    expected = hmac.new(
        secret.encode(), f"{version}.{body}".encode(), hashlib.sha256,
    ).digest()
    # compare_digest, not ==: a byte-at-a-time comparison leaks how much of a
    # forged signature was right, which is enough to build one.
    if not hmac.compare_digest(_b64(expected), presented):
        return None

    try:
        payload = json.loads(_unb64(body))
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None

    login = str(payload.get("l") or "").strip()
    expires = payload.get("e")
    # Both required. A signed payload with no login would otherwise build a
    # viewer with an empty one, and an empty login asked of an allow-list or
    # a collaborator check is a question nobody meant to ask.
    if not login or not isinstance(expires, int):
        return None
    if expires <= int(time.time()):
        return None

    return Viewer(
        login=login,
        user_id=str(payload.get("i") or "").strip(),
        # The login as the fallback, matching client_viewer: an account with
        # no display name should still render as something, and the login is
        # the only string we know belongs to them.
        display_name=str(payload.get("n") or "").strip() or login,
    )
