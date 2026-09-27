"""Security response headers for everything a browser loads.

Middleware rather than a per-route dependency, for the opposite reason
csrf.verify is per-route: a missing header is a silent weakening that
nothing fails on, so the default has to be "applied", with a small
explicit list of opt-outs. csrf.verify had to be per-route because it
must run AFTER an authorization decision; nothing here depends on
identity, so there is no ordering to respect.

WHAT EACH ONE IS FOR, since a header list with no reasons attached is
the kind of thing that gets "tidied up" later:

  frame-ancestors 'none' (+ X-Frame-Options for what predates it)
      The dashboard runs on a cookie session, so a page that can frame it
      can clickjack "Run audit" -- real spend, on a click the operator
      aimed somewhere else. The CSRF token does not help: a framed click
      is a genuine same-site submit from our own form.

  script-src 'self' 'nonce-...' with NO 'unsafe-inline'
      This dashboard renders repository names, PR titles, scanner
      messages and Markdown summaries, all of which a pull-request author
      controls. Autoescaping is the primary defence; this is what makes a
      single missed escape survivable. The nonce is per response, because
      a fixed one is a permanently valid one.

      'unsafe-inline' must never be added alongside the nonce: a browser
      seeing both IGNORES the nonce and allows all inline script.

  default-src 'none'
      So that the next sink somebody uses -- an iframe, a websocket, a
      beacon -- is denied until it is explicitly allowed, instead of
      allowed until somebody notices.

  style-src-attr 'unsafe-inline'
      Grudging, and narrow. The bar charts set widths and heights from
      computed numbers via style="width: N%", which cannot be expressed
      in a stylesheet. This permits inline style ATTRIBUTES only -- not
      <style> blocks, and nothing about script. The values are numbers
      passed through Jinja's |round, not text from a repository.

  X-Content-Type-Options: nosniff
      Stored reports are served as escaped text. A browser guessing that
      one is HTML would undo that.

  Referrer-Policy: no-referrer
      Dashboard URLs carry owner, repo and PR number. Clicking a link in
      a report should not hand those to the destination. no-referrer,
      not strict-origin-when-cross-origin, because the origin alone would
      still disclose that this deployment exists.

  Strict-Transport-Security, on HTTPS requests only
      Sent over local plaintext http it would be ignored by browsers, but
      it would also be a false assertion, and a header that is sometimes
      untrue is one nobody trusts.

  Cross-Origin-Opener-Policy / Permissions-Policy
      Cheap, and they close capabilities this app has no use for at all.

NOT EXCLUDED: /static. A stylesheet served with a guessable content type
is exactly what nosniff is for. Only the machine endpoints opt out, and
they do so because a CSP on a JSON probe protects nothing while HSTS on
a health check is a surprise for whatever is polling it.
"""

from __future__ import annotations

import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

# Machine clients, not browsers. /webhook is GitHub, and the other three
# are probes and a Prometheus scrape.
EXEMPT_PATHS = ("/webhook", "/health", "/ready", "/metrics")

HSTS = "max-age=31536000; includeSubDomains"

_STATIC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
}


def policy(nonce: str) -> str:
    """The CSP, built around this response's nonce.

    Ordered widest-to-narrowest so the fallback reads first; every
    directive that follows exists because something on the page needs it,
    and the tests in tests/api/test_security_headers.py name which.
    """
    return "; ".join([
        "default-src 'none'",
        f"script-src 'self' 'nonce-{nonce}'",
        # fonts.googleapis.com serves the @font-face stylesheet itself.
        "style-src 'self' https://fonts.googleapis.com",
        # The charts' computed widths. Attributes only -- see the module
        # docstring.
        "style-src-attr 'unsafe-inline'",
        "font-src https://fonts.gstatic.com",
        # No template loads an image today; 'self' rather than 'none' so a
        # favicon does not need a CSP change, and no data: because nothing
        # needs one -- data: URIs in img-src are a known exfiltration
        # channel and are not worth allowing speculatively.
        "img-src 'self'",
        # The audit page polls its own status with fetch.
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "object-src 'none'",
    ])


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds the headers, and hands the templates their nonce.

    The nonce is minted HERE and stashed on request.state, because the
    same value has to appear in the header and in every inline <script>.
    Middleware runs before the route, so dashboard._page can read it off
    the request when it builds the template context.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        exempt = request.url.path.startswith(EXEMPT_PATHS)

        nonce = secrets.token_urlsafe(16)
        # Set even on an exempt path: cheap, and it means a template
        # rendered from an unexpected route cannot read a missing
        # attribute.
        request.state.csp_nonce = nonce

        response = await call_next(request)
        if exempt:
            return response

        for name, value in _STATIC_HEADERS.items():
            response.headers[name] = value
        response.headers["Content-Security-Policy"] = policy(nonce)

        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        if proto == "https":
            response.headers["Strict-Transport-Security"] = HSTS

        return response
