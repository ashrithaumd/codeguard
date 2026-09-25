import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.exceptions import HTTPException as StarletteHTTPException

from codeguard.api.auth import require_metrics_token
from codeguard.api.routes.dashboard import (
    STATIC_DIR,
    asset_version,
    router as dashboard_router,
    templates,
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


async def _on_sweep(result) -> None:
    """Reaper callback: best-effort dead-letter notice for every job the
    reaper itself dead-lettered (a crash-looping worker that never called
    nack()). The other dead-lettering path — nack() exhausting attempts —
    is handled directly in the worker; this covers the path that doesn't
    go through the worker at all.
    """
    for dead_letter in result.dead_lettered:
        await notify_dead_letter(dead_letter)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # In lifespan, not at import: tests/api/conftest.py imports this
    # module, so a module-level exit would break collection. Startup is
    # also the right moment — uvicorn should refuse to serve, not accept
    # webhooks it cannot review.
    verify_required_settings()
    settings = get_settings()
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
            on_sweep=_on_sweep,
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
app.include_router(health_router)
app.include_router(webhooks_router)
app.include_router(dashboard_router)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """HTML error pages for the dashboard, JSON everywhere else.

    Keyed on the path rather than on content negotiation: /webhook is
    called by GitHub, which sends no useful Accept header, and a
    browser-shaped HTML body in a webhook response would be actively
    confusing in a delivery log.
    """
    if not request.url.path.startswith("/dashboard"):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    title, body = _ERROR_COPY.get(
        exc.status_code,
        ("Something went wrong", "That request could not be completed."),
    )
    return templates.TemplateResponse(
        request=request, name="error.html", status_code=exc.status_code,
        context={"status": exc.status_code, "title": title, "body": body,
                 "principal": None, "asset_version": asset_version()},
    )


# 404 covers both "no such review" and "not yours" — routes/dashboard.py
# answers 404 for both deliberately, so this copy must not hint at which.
_ERROR_COPY = {
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
