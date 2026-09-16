import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from codeguard.api.routes.health import router as health_router
from codeguard.api.routes.webhooks import router as webhooks_router
from codeguard.config import get_settings
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


@app.get("/metrics")
async def metrics(request: Request):
    await refresh_live_gauges(request.app.state.pool)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
