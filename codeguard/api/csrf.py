"""Cross-site request forgery protection for the dashboard's one POST.

WHY THIS IS NEEDED AT ALL, given the route is already authorized: the
authorization is by IDENTITY, and identity arrives in a cookie that the
browser attaches to any request to our origin. A form on any page the
operator visits while signed in produces a request the route cannot tell
from a real click. Triggering an audit clones a repository, spends
Anthropic credit, and occupies the one in-flight slot that user is
allowed, so a page they merely visit can bill them and lock them out.

TWO CHECKS, because each covers the other's hole:

  1. Origin (Referer as fallback). Script cannot forge either, so a
     cross-site POST is identifiable. Fails open when both are absent.
  2. A double-submit token: a random value in a SameSite=Strict cookie,
     echoed back in a hidden form field. An attacker's page cannot read
     our cookie, so it cannot supply the matching field. Fails if an
     attacker can WRITE our cookies -- a sibling host on a shared parent
     domain, which this deployment has, since Container Apps serves it
     from *.azurecontainerapps.io alongside other tenants' apps.

Check 1 covers check 2's cookie-writing attacker (their Origin still
differs); check 2 covers check 1's missing-header client. Neither alone
is enough here.

NO SERVER SECRET, deliberately. A signed stateless token would need one,
and a secret that is unset in local dev either disables the protection
or is silently generated per process -- which breaks every form the
moment the API runs more than one replica. A random cookie needs no
configuration, works identically in compose and in Azure, and cannot be
misconfigured into fail-open.
"""

from __future__ import annotations

import hmac
import logging
import secrets
from urllib.parse import urlsplit

from fastapi import Request, Response

logger = logging.getLogger(__name__)

COOKIE_NAME = "cg_csrf"
FIELD_NAME = "csrf_token"

# 32 bytes of urandom, hex. Long enough that guessing is not a strategy;
# short enough to sit in a cookie and a hidden input without comment.
_TOKEN_BYTES = 32

# What a caller is told. Deliberately actionable and free of detail: the
# overwhelmingly likely cause of a genuine user seeing this is a page left
# open long enough for the cookie to be cleared, not an attack.
FAILURE_MESSAGE = (
    "That request could not be verified. Please reload the Repositories "
    "page and try again."
)


def _looks_like_a_token(value: str) -> bool:
    return len(value) == _TOKEN_BYTES * 2 and all(
        c in "0123456789abcdef" for c in value
    )


def token(request: Request) -> str:
    """This browser's token, minted if it does not have one yet.

    Reuses the existing cookie rather than rotating per render: a token
    that changed on every page load would invalidate the form in the
    user's other tab, and after the back button.

    Split from `attach` because a Starlette TemplateResponse RENDERS IN
    ITS CONSTRUCTOR -- the token has to be in the context before the
    response object exists, so it cannot be produced as a side effect of
    setting a cookie on one.
    """
    existing = request.cookies.get(COOKIE_NAME, "")
    if _looks_like_a_token(existing):
        return existing
    return secrets.token_hex(_TOKEN_BYTES)


def attach(request: Request, response: Response, value: str) -> None:
    """Set the cookie, unless the request already carried this same one.

    `secure` follows the scheme the request actually arrived on, read from
    x-forwarded-proto because Container Apps terminates TLS at the
    ingress and this app sees http. Hardcoding secure=True would mean the
    cookie is never sent over local compose's http, so every form would
    fail with no obvious cause; hardcoding False would let the token ride
    a plaintext connection in production.
    """
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    response.set_cookie(
        COOKIE_NAME, value,
        # Strict, not Lax: this cookie is only ever read by our own
        # same-site form post, so there is no cross-site navigation that
        # needs it, and Strict means a conforming browser will not attach
        # it to a cross-site POST at all -- a third layer, under the two
        # checks in verify().
        samesite="strict",
        # Nothing in the page reads it; the token is rendered server-side.
        httponly=True,
        secure=proto == "https",
        path="/",
        max_age=60 * 60 * 12,
    )


def _request_host(request: Request) -> str:
    """The host this request was addressed to, as the browser saw it.

    x-forwarded-host first: behind the Container Apps ingress the Host
    header can be the internal one, and comparing an attacker's Origin
    against the wrong host would either reject everything or accept
    everything.
    """
    forwarded = request.headers.get("x-forwarded-host", "")
    if forwarded:
        return forwarded.split(",")[0].strip().lower()
    return (request.headers.get("host") or request.url.netloc).lower()


def _cross_site(request: Request) -> bool:
    """True only when a header is PRESENT and names another origin.

    Absent headers are not treated as cross-site -- see the module
    docstring and test_a_post_with_neither_origin_nor_referer_is_allowed_
    with_a_good_token. The token check is what holds in that case.
    """
    stated = request.headers.get("origin") or request.headers.get("referer") or ""
    if not stated:
        return False
    # "null" is what a sandboxed iframe or a redirected cross-origin POST
    # sends. It is not our origin, so it is cross-site.
    if stated == "null":
        return True
    return urlsplit(stated).netloc.lower() != _request_host(request)


async def verify(request: Request) -> None:
    """Raise if this POST did not come from our own page.

    Reads the form itself rather than taking a FastAPI Form parameter, so
    a missing field is a CSRF failure rather than a 422 validation error
    -- a 422 would be a confusing answer to a security refusal, and would
    report the field name back to the caller.

    Caller's responsibility: run this AFTER the authorization gate. This
    route answers 404 to anyone not allowed to audit, and a 403 from here
    ahead of that would tell a stranger the facility exists. See
    test_an_unauthorised_caller_still_gets_404_not_403.
    """
    from fastapi import HTTPException

    if _cross_site(request):
        logger.warning(
            "CSRF: cross-site %s to %s (origin=%r referer=%r host=%r)",
            request.method, request.url.path,
            request.headers.get("origin"), request.headers.get("referer"),
            _request_host(request),
        )
        raise HTTPException(status_code=403, detail=FAILURE_MESSAGE)

    cookie = request.cookies.get(COOKIE_NAME, "")
    form = await request.form()
    submitted = str(form.get(FIELD_NAME) or "")

    # Fail closed on an absent cookie. compare_digest("", "") is True, so
    # without this an attacker who can strip cookies -- or a request that
    # simply never had one -- would pass by submitting nothing.
    if not _looks_like_a_token(cookie) or not hmac.compare_digest(cookie, submitted):
        logger.warning(
            "CSRF: token mismatch on %s (cookie_present=%s field_present=%s)",
            request.url.path, bool(cookie), bool(submitted),
        )
        raise HTTPException(status_code=403, detail=FAILURE_MESSAGE)
