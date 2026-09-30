"""This app's own GitHub OAuth sign-in, for DASHBOARD_AUTH_MODE=app.

WHY, since EasyAuth already worked. Three things it cannot do, and the first
one has already cost real time:

  * SHOW GITHUB'S ACCOUNT PICKER. `prompt=select_account` is documented by
    GitHub, and EasyAuth drops it — measured: unknown query parameters do not
    reach the authorize URL, and the GitHub provider exposes no
    loginParameters to put it in. With two accounts on one machine GitHub
    silently reuses whichever session it holds, which presents as "I signed
    in and the dashboard says I am someone else", and was reported as a
    broken session.
  * END A SESSION. EasyAuth's logout clears its own cookie; there is no
    session of ours to end, so nothing we do can make the next sign-in ask.
  * GET A USER-TO-SERVER TOKEN, which phase 2 needs to list a visitor's own
    repositories. Under EasyAuth there is no token at all unless the token
    store is enabled, which was deliberately rejected.

WHAT IS DELIBERATELY NOT DONE HERE: no PKCE. It protects a public client from
an intercepted authorization code, and this is a confidential client — the
code is exchanged server-side with a client secret the browser never sees, so
an intercepted code is useless without it. Adding PKCE would be harmless but
it would be decoration, and decoration in an auth flow is a thing future
readers must reason about.

THE THREE WAYS THIS SHAPE OF FLOW IS USUALLY GOT WRONG:

 1. No state check. Without one, an attacker authorizes THEIR account,
    hands the resulting code to a victim's browser, and the victim ends up
    signed into the attacker's account — where they may then connect their
    own repositories. The state here must be present, must match a cookie
    the attacker cannot set, and is single-use.
 2. An open redirect in `next`. Only local paths are honoured, because
    "https://evil.example" behind a link that genuinely starts on our own
    domain is a convincing phishing step.
 3. A leaking token. It never enters a cookie, a body or a URL: a token in a
    URL is a token in browser history, in Referer, and in every proxy log.
"""

from __future__ import annotations

import hmac
import logging
import secrets

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from codeguard.api import session, user_tokens
from codeguard.config import get_settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"

STATE_COOKIE = "cg_oauth_state"
# The round trip to GitHub and back, generously. Long enough for somebody to
# read an authorization screen and pick an account; short enough that an
# abandoned attempt does not leave a usable state lying around.
STATE_TTL_SECONDS = 600

# Where sign-in lands when no usable `next` was given. The signed-in home.
DEFAULT_NEXT = "/dashboard/repos"

HTTP_TIMEOUT = 10


def _secure(request: Request) -> bool:
    """Whether to mark cookies Secure.

    From x-forwarded-proto, because Container Apps terminates TLS and the app
    itself sees http. Hardcoding True breaks local compose (the cookie is
    never sent back, so sign-in silently fails); hardcoding False would let a
    session ride plaintext in production.
    """
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"


def safe_next(raw: str | None) -> str:
    """A local path, or the default. Never anything that leaves this origin.

    Rejects a scheme, a protocol-relative "//host", and a backslash — the
    last because some browsers normalise "/\\evil.example" into a
    protocol-relative URL, which is the classic way this check gets bypassed
    after somebody "simplified" it to `startswith("/")`.
    """
    if not raw or not raw.startswith("/"):
        return DEFAULT_NEXT
    if raw.startswith("//") or raw.startswith("/\\"):
        return DEFAULT_NEXT
    if ":" in raw.split("/", 2)[1] if len(raw.split("/", 2)) > 1 else False:
        return DEFAULT_NEXT
    return raw


def _exchange_code_for_token(code: str, *, redirect_uri: str = "") -> str:
    """The authorization code for a user-to-server token, server-side.

    A seam of its own so tests can stand in for GitHub by name rather than by
    patching `requests` and hoping the right call was intercepted.
    """
    settings = get_settings()
    resp = requests.post(
        TOKEN_URL,
        data={
            "client_id": settings.github_oauth_client_id,
            "client_secret": settings.github_oauth_client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        },
        headers={"Accept": "application/json"},
        timeout=HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    body = resp.json()
    token = body.get("access_token") or ""
    if not token:
        # body.get("error") is safe to log -- it is GitHub's error CODE, not
        # the secret or the code. The token itself is never logged anywhere.
        logger.warning("GitHub token exchange returned no token: %r", body.get("error"))
    return token


def _fetch_github_user(token: str) -> dict:
    """Who that token belongs to: login, numeric id, display name."""
    resp = requests.get(
        USER_URL,
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json"},
        timeout=HTTP_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


@router.get("/login")
async def login(request: Request):
    """Start the flow: set a state cookie, redirect to GitHub's picker."""
    settings = get_settings()
    if not settings.github_oauth_client_id or not settings.github_oauth_client_secret:
        # Fail here rather than bounce the user to GitHub for a flow that
        # cannot complete -- they would authorize and then hit an error,
        # having granted something for nothing.
        logger.error("sign-in attempted with no OAuth client id/secret configured")
        raise HTTPException(
            status_code=500,
            detail="Sign-in is not configured on this deployment.",
        )

    state = secrets.token_urlsafe(32)
    target = safe_next(request.query_params.get("next"))
    redirect_uri = str(request.url_for("oauth_callback"))

    params = {
        "client_id": settings.github_oauth_client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        # The entire point. Without it GitHub reuses whatever session it
        # holds and never asks which account.
        "prompt": "select_account",
    }
    query = "&".join(f"{k}={requests.utils.quote(v, safe='')}" for k, v in params.items())
    response = RedirectResponse(url=f"{AUTHORIZE_URL}?{query}", status_code=302)
    # Lax, NOT Strict: this cookie has to survive a top-level navigation back
    # from github.com, and Strict would not be sent on it -- which would make
    # every sign-in fail the state check.
    response.set_cookie(
        STATE_COOKIE, f"{state}|{target}",
        max_age=STATE_TTL_SECONDS, httponly=True,
        secure=_secure(request), samesite="lax", path="/",
    )
    return response


@router.get("/callback", name="oauth_callback")
async def callback(request: Request):
    """GitHub's return leg: check state, exchange the code, mint a session."""
    settings = get_settings()
    code = request.query_params.get("code") or ""
    presented = request.query_params.get("state") or ""
    stored = request.cookies.get(STATE_COOKIE) or ""
    expected, _, target = stored.partition("|")

    # Fail closed on an absent cookie. compare_digest("", "") is True, so
    # without the emptiness check a request with no cookie and no state would
    # sail through -- the same trap the CSRF double-submit has.
    if not code or not presented or not expected or \
            not hmac.compare_digest(expected, presented):
        logger.warning(
            "OAuth callback refused (code=%s state=%s cookie=%s)",
            bool(code), bool(presented), bool(expected),
        )
        raise HTTPException(status_code=400, detail="Sign-in could not be completed. Please try again.")

    try:
        token = _exchange_code_for_token(
            code, redirect_uri=str(request.url_for("oauth_callback")),
        )
        if not token:
            raise HTTPException(status_code=400, detail="Sign-in could not be completed. Please try again.")
        profile = _fetch_github_user(token)
    except requests.RequestException as exc:
        # type(exc).__name__ only: a RequestException's text can embed the
        # request URL, and that URL carries the authorization code.
        logger.warning("OAuth exchange failed: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail="GitHub could not be reached. Please try again.") from None

    login_name = str(profile.get("login") or "").strip()
    user_id = str(profile.get("id") or "").strip()
    if not login_name:
        logger.error("GitHub returned a profile with no login")
        raise HTTPException(status_code=502, detail="GitHub could not be reached. Please try again.")

    value = session.issue(
        login=login_name,
        user_id=user_id,
        # The login when GitHub has no display name set, matching
        # client_viewer: an account should still render as something.
        display_name=str(profile.get("name") or "").strip() or login_name,
        secret=settings.session_secret,
    )

    # Keep the token server-side for phase 2. Best-effort: a storage failure
    # must not stop somebody signing in, because the session does not depend
    # on it and nothing consumes it yet. Logged as a warning so it does not
    # become a silent gap later, when something does.
    pool = getattr(request.app.state, "pool", None)
    if pool is not None and user_id:
        try:
            await user_tokens.store(
                pool, user_id=user_id, login=login_name, access_token=token,
            )
        except Exception as exc:  # noqa: BLE001 - never block a sign-in
            logger.warning("could not store the GitHub user token: %s", type(exc).__name__)

    response = RedirectResponse(url=safe_next(target), status_code=303)
    response.set_cookie(
        session.COOKIE_NAME, value,
        max_age=session.DEFAULT_TTL_SECONDS, httponly=True,
        secure=_secure(request), samesite="lax", path="/",
    )
    # SINGLE USE. Clearing it here means a replayed callback finds no cookie
    # to match against, so one authorization cannot mint two sessions.
    response.delete_cookie(STATE_COOKIE, path="/")
    logger.info("signed in %s (id=%s)", login_name, user_id)
    return response


@router.post("/logout")
async def logout(request: Request):
    """End the session. POST, not GET: a GET logout can be triggered by any
    page embedding it as an image, and while being signed out is only an
    annoyance, avoiding it is free."""
    target = safe_next(request.query_params.get("next"))
    response = RedirectResponse(url=target, status_code=303)
    response.delete_cookie(session.COOKIE_NAME, path="/")
    return response
