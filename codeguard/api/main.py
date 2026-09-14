import logging

from fastapi import FastAPI
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from codeguard.api.routes.health import router as health_router
from codeguard.api.routes.webhooks import router as webhooks_router

# uvicorn configures its own loggers (uvicorn, uvicorn.error, uvicorn.access)
# but never touches the root logger, which defaults to WARNING-and-above
# with no handler. Without this, every logger.info() in codeguard's own
# modules is silently dropped — only warning()/error() calls would show.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

app = FastAPI(title="CodeGuard API")
app.include_router(health_router)
app.include_router(webhooks_router)


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
