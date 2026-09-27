"""Who is asking, and may they see /metrics.

Two unrelated gates that happen to both be "auth", kept in one small
module because both are request-scoped facts the routes need and
neither is big enough to own a file:

- `require_metrics_token` guards /metrics with a bearer token, because
  Prometheus is a machine client and cannot follow a login redirect.
- `client_principal` reads the identity Azure Container Apps' built-in
  auth (EasyAuth) injects, for the dashboard.

EasyAuth runs in AllowAnonymous mode in front of this app: it does NOT
reject anonymous requests, it annotates authenticated ones and passes
everything through. Authorization is this app's job — see
codeguard/api/access.py.
"""

from __future__ import annotations

import hmac
import logging

from fastapi import HTTPException, Request

from codeguard.config import get_settings

logger = logging.getLogger(__name__)

# EasyAuth injects these on an authenticated request and STRIPS them
# from an unauthenticated one, including when a client sends them
# itself — that stripping is the entire basis for trusting the header.
# It only holds while requests reach this app through the ingress
# EasyAuth fronts; anything that bypasses that ingress (a direct pod
# connection, a future sidecar) could forge it.
_PRINCIPAL_HEADER = "X-MS-CLIENT-PRINCIPAL-NAME"


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


def client_principal(request: Request) -> str | None:
    """The signed-in GitHub login, or None for an anonymous visitor.

    The dev override exists because nothing injects this header when the
    app runs under plain uvicorn. It requires BOTH a username and an
    explicit opt-in flag: a single setting would mean a deployment that
    forgot to clear one env var would accept a forged identity, and the
    two-key form makes that a deliberate act rather than an oversight.
    """
    settings = get_settings()
    if settings.dashboard_trust_dev_principal and settings.dashboard_dev_principal:
        return settings.dashboard_dev_principal

    principal = request.headers.get(_PRINCIPAL_HEADER, "").strip()
    return principal or None
