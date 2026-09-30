"""Who is asking, and may they see /metrics.

Two unrelated gates that happen to both be "auth", kept in one small
module because both are request-scoped facts the routes need and
neither is big enough to own a file:

- `require_metrics_token` guards /metrics with a bearer token, because
  Prometheus is a machine client and cannot follow a login redirect.
- `client_viewer` / `client_principal` read the identity Azure Container
  Apps' built-in auth (EasyAuth) injects, for the dashboard. The login
  comes from the claims blob, never from the display name — see the
  comment on _PRINCIPAL_HEADER for what that cost.

EasyAuth runs in AllowAnonymous mode in front of this app: it does NOT
reject anonymous requests, it annotates authenticated ones and passes
everything through. Authorization is this app's job — see
codeguard/api/access.py.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
from dataclasses import dataclass

from fastapi import HTTPException, Request

from codeguard.config import get_settings

logger = logging.getLogger(__name__)

# EasyAuth injects these on an authenticated request and STRIPS them
# from an unauthenticated one, including when a client sends them
# itself — that stripping is the entire basis for trusting the header.
# It only holds while requests reach this app through the ingress
# EasyAuth fronts; anything that bypasses that ingress (a direct pod
# connection, a future sidecar) could forge it.
#
# THE CLAIMS BLOB, NOT THE NAME HEADER.
#
# X-MS-CLIENT-PRINCIPAL-NAME is built from EasyAuth's `name_typ`, which for
# the GitHub provider is claims/name — the DISPLAY NAME. Identifying users
# by it meant every access decision asked GitHub about a collaborator who
# does not exist. Measured on the deployed build: 11 repositories installed,
# 11 fetched, 0 rendered, for everyone including the owner.
#
# It was not merely an outage. A display name is free text, mutable and NOT
# UNIQUE, and the collision is not hypothetical — the two accounts this
# deployment is tested with share one:
#
#     ashrithaumd   183667058   Ashritha Pola
#     AshrithaPola   60956648   Ashritha Pola
#
# It failed CLOSED, because the allow-list held a login and neither display
# name matched it. The tempting repair — putting the display name in the
# allow-list — would have handed operator rights, and the Anthropic bill, to
# whoever else happened to share it.
#
# These claim names were read off a live request rather than taken from
# documentation; the observed claim set is in the git history, under the
# temporary EASYAUTH-DIAG commits.
_PRINCIPAL_HEADER = "X-MS-CLIENT-PRINCIPAL-NAME"
_CLAIMS_HEADER = "X-MS-CLIENT-PRINCIPAL"
_LOGIN_CLAIM = "urn:github:login"
_ID_CLAIM = "urn:github:id"
_NAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"


@dataclass(frozen=True)
class Viewer:
    """Who is asking, with each field limited to what it is fit for.

    login        GitHub's username. Every repo-access decision uses this,
                 because GitHub's collaborator endpoint is keyed on it.
                 Rename-safe by construction: after a rename EasyAuth
                 reports the new login and GitHub answers for the new
                 login, so the two cannot disagree.
    user_id      GitHub's immutable numeric id. The operator allow-list
                 matches on this — it is the one place a name is STORED,
                 and therefore the one place a rename matters, because a
                 released login can be registered by somebody else.
    display_name For showing a human their own name in the nav. NEVER a
                 decision: free text, mutable, not unique.
    """

    login: str
    user_id: str
    display_name: str


def require_metrics_token(request: Request) -> None:
    """FastAPI dependency: 401 unless the request carries the configured
    bearer token.

    Unset token means the endpoint is open, which is how local compose
    and a developer's curl keep working. That is a deliberate
    fail-OPEN, and it is the opposite of every other default in this
    codebase — justified only because the alternative is that a missing
    env var silently breaks metrics collection in every environment at
    once. api/main.py warns loudly at startup when it is unset, so this
    cannot be open in production without someone having been told.

    Compared with compare_digest: a token check that short-circuits on
    the first wrong byte leaks the token's prefix to anyone who can
    time the response.
    """
    expected = get_settings().metrics_auth_token
    if not expected:
        return

    header = request.headers.get("Authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(presented, expected):
        # No WWW-Authenticate challenge: this endpoint has exactly one
        # non-interactive client and a challenge would only invite a
        # browser to prompt for credentials that do not exist.
        raise HTTPException(status_code=401, detail="metrics requires a bearer token")


def _claims(request: Request) -> dict[str, str] | None:
    """EasyAuth's claims blob as {claim type: value}, or None.

    Quiet about an absent header, because an anonymous request legitimately
    has none and a warning there would fire on every anonymous page view.
    Loud about a present-but-unreadable one, because that IS anomalous —
    either a proxy mangled it or the format changed under us, and since this
    fails closed that would present as an outage and must be visible.
    """
    blob = request.headers.get(_CLAIMS_HEADER, "")
    if not blob:
        return None
    try:
        # Padding is stripped in some configurations; altchars covers the
        # base64url variant. Standard base64 decodes either way, since the
        # two alphabets differ only in the last two characters.
        padded = blob + "=" * (-len(blob) % 4)
        decoded = json.loads(base64.b64decode(padded, altchars=b"-_"))
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        logger.warning(
            "EasyAuth claims header present but undecodable (%s) — treating the "
            "request as anonymous", type(exc).__name__,
        )
        return None

    claims = decoded.get("claims") if isinstance(decoded, dict) else None
    if not isinstance(claims, list):
        return None

    out: dict[str, str] = {}
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        typ, val = claim.get("typ"), claim.get("val")
        # First occurrence wins. A blob carrying the same claim twice is not
        # something to resolve by preferring the last one seen.
        if isinstance(typ, str) and isinstance(val, str) and typ not in out:
            out[typ] = val
    return out


def client_viewer(request: Request) -> Viewer | None:
    """Who is signed in, or None for an anonymous visitor.

    Identity comes from urn:github:login, NOT from the NAME header, and
    there is NO FALLBACK to the display name. If the login claim is missing
    we cannot say who this is, and "cannot say" has to mean anonymous
    rather than "use whichever other string is to hand" — that fallback is
    precisely the bug described above _PRINCIPAL_HEADER.

    The dev override exists because nothing injects these headers when the
    app runs under plain uvicorn. It still requires BOTH a username and an
    explicit opt-in flag: a single setting would mean a deployment that
    forgot to clear one env var would accept a forged identity, and the
    two-key form makes that a deliberate act rather than an oversight.
    """
    settings = get_settings()
    if settings.dashboard_trust_dev_principal and settings.dashboard_dev_principal:
        login = settings.dashboard_dev_principal
        return Viewer(
            login=login,
            # Separate setting, so a local run cannot accidentally hold
            # operator rights just by naming a login.
            user_id=settings.dashboard_dev_principal_id,
            display_name=login,
        )

    # EXACTLY ONE SOURCE PER MODE, and an unknown mode trusts nothing.
    #
    # In "app" mode the EasyAuth header is IGNORED even when present. That is
    # the whole security argument for the switch: once sign-in is ours, Azure
    # no longer strips X-MS-CLIENT-PRINCIPAL, so it becomes attacker-
    # controlled like any other header. Reading whichever source answered
    # first would hand anyone any identity — the forged-blob attack that is
    # impossible today only because the platform blocks it.
    #
    # A typo in the env var falls through to None: nobody is signed in, which
    # is loud and safe rather than quiet and dangerous.
    mode = (settings.dashboard_auth_mode or "").strip().lower()
    if mode == "app":
        # Imported here, not at module scope: session.py imports Viewer from
        # this module, and a top-level import would be circular.
        from codeguard.api import session

        return session.verify(
            request.cookies.get(session.COOKIE_NAME), secret=settings.session_secret,
        )
    if mode != "easyauth":
        logger.warning(
            "DASHBOARD_AUTH_MODE is %r, which is not 'easyauth' or 'app' — "
            "treating every request as signed out", settings.dashboard_auth_mode,
        )
        return None

    claims = _claims(request)
    if not claims:
        return None
    login = (claims.get(_LOGIN_CLAIM) or "").strip()
    if not login:
        return None
    return Viewer(
        login=login,
        user_id=(claims.get(_ID_CLAIM) or "").strip(),
        # The login when no display name is set: an account without one
        # should still show as something, and the login is the only string
        # we actually know belongs to them.
        display_name=(claims.get(_NAME_CLAIM) or "").strip() or login,
    )


def client_principal(request: Request) -> str | None:
    """The signed-in GitHub LOGIN, or None for an anonymous visitor.

    Kept as a name and a signature because two dozen call sites pass this
    into access checks and store it as `requested_by`. What changed is where
    the value comes from: it is the login now, which is what every one of
    those call sites already believed it was — including this docstring,
    which said "login" throughout while the function returned a display
    name.
    """
    viewer = client_viewer(request)
    return viewer.login if viewer else None
