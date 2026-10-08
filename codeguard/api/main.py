import asyncio
import logging
import os
from collections.abc import Mapping
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.exceptions import HTTPException as StarletteHTTPException

from codeguard.api import audits
from codeguard.api.auth import client_principal, require_metrics_token
from codeguard.api.headers import SecurityHeadersMiddleware
from codeguard.api.oauth import router as oauth_router
from codeguard.api.routes.dashboard import (
    STATIC_DIR,
    render_page,
    router as dashboard_router,
)
from codeguard.api.routes.health import router as health_router
from codeguard.api.routes.webhooks import router as webhooks_router
from codeguard.config import get_settings, verify_required_settings
from codeguard.github.notifications import notify_dead_letter
from codeguard.queue import reaper
from codeguard.queue.db import bootstrap_schema, create_pool
from codeguard.queue.metrics import refresh_live_gauges

# uvicorn configures its own loggers (uvicorn, uvicorn.error, uvicorn.access)
# but never touches the root logger, which defaults to WARNING-and-above
# with no handler. Without this, every logger.info() in codeguard's own
# modules is silently dropped — only warning()/error() calls would show.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("codeguard.api")


class DevPrincipalInAzure(RuntimeError):
    """DASHBOARD_TRUST_DEV_PRINCIPAL is on inside Azure Container Apps."""


def refuse_dev_principal_in_azure(settings, environ: Mapping[str, str]) -> None:
    """Refuse to start with the dev-principal override inside Azure.

    The override forces every dashboard visitor's identity to one login and
    ignores the EasyAuth header -- locally, how the dashboard is driven
    without GitHub; deployed, the operator's identity and audit button for
    anyone who can reach the URL. It was a startup warning. In Azure it is
    now a refusal, because a crash-looping revision is noticed and a log
    line is not.

    CONTAINER_APP_NAME is set by the Container Apps runtime in every
    container it runs, and by nothing on a developer machine.
    """
    if settings.dashboard_trust_dev_principal and environ.get("CONTAINER_APP_NAME"):
        raise DevPrincipalInAzure(
            "DASHBOARD_TRUST_DEV_PRINCIPAL is set, and this is running in Azure Container Apps "
            f"({environ['CONTAINER_APP_NAME']!r}). It forces every dashboard visitor's identity "
            "and must never be enabled in a deployment. Remove it from the app's environment."
        )


async def _on_sweep(pool, result) -> None:
    """Reaper callback: best-effort dead-letter notice for every job the
    reaper itself dead-lettered (a crash-looping worker that never called
    nack()). The other dead-lettering path — nack() exhausting attempts —
    is handled directly in the worker; this covers the path that doesn't
    go through the worker at all.

    Takes `pool` because failing the corresponding audit needs a write.
    The reaper passes only the ReapResult, so lifespan binds the pool in
    when it registers the callback.
    """
    for dead_letter in result.dead_lettered:
        # Before the notice, because this is the one that unblocks a
        # repository: an audit left 'running' by a dead worker holds
        # audits_one_in_flight_per_repo forever. See
        # audits.fail_audit_for_dead_letter.
        await audits.fail_audit_for_dead_letter(pool, dead_letter)
        await notify_dead_letter(dead_letter)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # In lifespan, not at import: tests/api/conftest.py imports this
    # module, so a module-level exit would break collection. Startup is
    # also the right moment — uvicorn should refuse to serve, not accept
    # webhooks it cannot review.
    verify_required_settings()
    settings = get_settings()
    # Before the pool, before anything is served.
    refuse_dev_principal_in_azure(settings, os.environ)
    pool = await create_pool(settings)
    await bootstrap_schema(pool)
    app.state.pool = pool

    # Reaper: a background asyncio task inside this (single-instance) API
    # process, not the worker — see codeguard/queue/reaper.py's module
    # docstring for why. TODO: api must stay single-replica in Azure
    # Container Apps for "sweeps never race each other" to hold; if api
    # ever needs to scale horizontally, the reaper needs to move to its
    # own dedicated single-instance process first.
    reaper_task = asyncio.create_task(
        reaper.run_forever(
            pool,
            interval_seconds=settings.reaper_interval_seconds,
            max_attempts=settings.max_delivery_attempts,
            # Bound to this lifespan's pool: the reaper hands the callback
            # only a ReapResult, and failing a dead-lettered audit needs a write.
            on_sweep=lambda result: _on_sweep(pool, result),
        )
    )
    logger.info("reaper started (interval=%ss, max_attempts=%d)",
                settings.reaper_interval_seconds, settings.max_delivery_attempts)

    # Loud, because the failure is invisible from the outside: an
    # unauthenticated /metrics answers normally and looks healthy while
    # serving repo names, job counts and cost to anyone who asks. It was
    # publicly reachable on the Container Apps ingress until this was
    # added. Expected to be empty in local compose, where Prometheus
    # scrapes it over the compose network.
    if not settings.metrics_auth_token:
        logger.warning(
            "METRICS_AUTH_TOKEN is not set — /metrics is UNAUTHENTICATED. Fine for local "
            "compose; on a public ingress it exposes repo names, job counts and cost."
        )
    # A misconfigured allow-list fails CLOSED, so its only symptom is a
    # button that is absent — indistinguishable from "not configured yet".
    # Naming the bad entries is the difference between a five-minute fix and
    # an afternoon. Entries are numeric GitHub user ids now, not logins; see
    # Settings.dashboard_audit_principals for why a login is inert rather
    # than accepted.
    if settings.audit_principals_ignored:
        logger.warning(
            "DASHBOARD_AUDIT_PRINCIPALS contains %d entry/entries that are not "
            "numeric GitHub user ids and are therefore IGNORED: %s. The audit "
            "button will be absent for them. Use the numeric id (GitHub's "
            "/users/<login> API reports it); a login is not accepted, because a "
            "renamed login can be re-registered by someone else.",
            len(settings.audit_principals_ignored),
            ", ".join(settings.audit_principals_ignored),
        )
    if settings.dashboard_trust_dev_principal:
        logger.warning(
            "DASHBOARD_TRUST_DEV_PRINCIPAL is on — dashboard identity is forced to %r and "
            "the EasyAuth header is ignored. Never enable this in a deployment.",
            settings.dashboard_dev_principal,
        )

    try:
        yield
    finally:
        reaper_task.cancel()
        try:
            await reaper_task
        except asyncio.CancelledError:
            pass
        await pool.close()


app = FastAPI(title="CodeGuard API", lifespan=lifespan)
app.add_middleware(SecurityHeadersMiddleware)
app.include_router(oauth_router)
app.include_router(health_router)
app.include_router(webhooks_router)
app.include_router(dashboard_router)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# Machine endpoints that live under /dashboard. A suffix and one exact
# path, rather than a list of every endpoint: `.json` is the convention
# this app already uses for "this is data", so a new poll endpoint is
# covered by naming itself correctly instead of by editing this.
_JSON_SUFFIX = ".json"
_JSON_PATHS = frozenset({"/dashboard/search"})


def _wants_json(path: str) -> bool:
    """Whether an error on this path should be JSON rather than an HTML page.

    Issue #6: the rule used to be the /dashboard prefix alone, so
    /dashboard/audits/{id}.json -- a machine endpoint that happens to live
    under the page prefix -- inherited the HTML branch and answered a 404
    with a full error page. The status was right and nothing leaked; the
    damage was in the poller, which treated it as a transient blip and
    backed off forever, leaving a deleted audit's page spinning.

    Still NOT content negotiation, for the original reason: /webhook is
    called by GitHub, which sends no useful Accept header, and an HTML body
    in a delivery log would be actively confusing. A path rule keeps that
    property while fixing the endpoints that were on the wrong side of it.
    """
    if not path.startswith("/dashboard"):
        return True
    return path.endswith(_JSON_SUFFIX) or path in _JSON_PATHS


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """HTML error pages for the dashboard's PAGES, JSON everywhere else.

    See _wants_json for where the line is and why it is drawn on the path.
    """
    if _wants_json(request.url.path):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    title, body = _ERROR_COPY.get(
        exc.status_code,
        ("Something went wrong", "That request could not be completed."),
    )
    # 400 is the one status whose detail is shown. Everywhere else the
    # canned copy is deliberate — 404's whole job is to read the same
    # for "no such thing" and "not yours", so echoing a detail there
    # would undo the conflation the routes went out of their way to
    # create. A 400 is different: it means the request was understood
    # and refused for a reason the caller can act on (auditing a private
    # repository, say), and hiding that reason leaves them with
    # "something went wrong" and nothing to do about it.
    if exc.status_code == 400 and exc.detail:
        body = exc.detail
    # render_page, NOT a TemplateResponse of our own. This handler used to
    # assemble its own context, which meant it silently missed csp_nonce
    # when that was added: every error page rendered nonce="" and had all
    # its scripts blocked by our own CSP. Anything else added to the page
    # contract in future would have gone the same way.
    # The REAL principal, not None. Passing None rendered every error page
    # with the signed-out nav, so a signed-in visitor hitting a legitimate
    # 404 — a review in a repository they cannot access — saw "Sign in with
    # GitHub" and read it as "my session did not stick". That cost real
    # diagnostic time on a session that was working perfectly.
    #
    # It looked deliberate, because the 404 copy advises signing in with an
    # account that can access the review, which is good advice for an
    # anonymous visitor. It is actively misleading for a signed-in one: it
    # names the wrong cause. The copy still appears for anonymous visitors,
    # who are the people it was written for.
    #
    # Indistinguishability is unaffected: one viewer asking about a missing
    # review and a forbidden one gets the same principal in both, so the two
    # bodies still match byte for byte.
    return render_page(
        request, "error.html", client_principal(request),
        status_code=exc.status_code,
        status=exc.status_code, title=title, body=body,
    )


# 404 covers both "no such review" and "not yours" — routes/dashboard.py
# answers 404 for both deliberately, so this copy must not hint at which.
_ERROR_COPY = {
    # A CSRF refusal is a page a person sees, so it gets copy of its own.
    # Without this it fell through to "Something went wrong — the dashboard
    # could not load this page", which is wrong twice over: nothing went
    # wrong, and it is not about loading. The overwhelmingly likely cause for
    # a real user is a page left open long enough for the cookie to expire,
    # so the copy says what to do rather than what happened.
    403: ("Couldn't verify that action",
          "This action could not be verified, usually because the page had been "
          "open for a while. Reload the page and try again."),
    409: ("Already running",
          "Someone is already auditing that repository. Please try again in a few minutes."),
    404: ("Not found",
          "This review either does not exist or is not visible to you. "
          "If it belongs to a private repository, sign in with a GitHub account that can access it."),
    500: ("Something went wrong",
          "The dashboard could not load this page. The error has been logged."),
}


@app.get("/metrics", dependencies=[Depends(require_metrics_token)])
async def metrics(request: Request):
    await refresh_live_gauges(request.app.state.pool)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
