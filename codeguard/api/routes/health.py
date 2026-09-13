from fastapi import APIRouter, Response

from codeguard.api.db import check_db_connection

router = APIRouter()


@router.get("/health")
async def health():
    """Liveness only — no dependency checks. Must stay true even if
    Postgres is down, so an orchestrator doesn't kill/restart a
    perfectly fine API container over a database blip.
    """
    return {"status": "ok"}


@router.get("/ready")
async def ready(response: Response):
    """Readiness — can this instance actually do its job. False (503)
    when Postgres isn't reachable.
    """
    db_ok = await check_db_connection()
    if not db_ok:
        response.status_code = 503
    return {"status": "ok" if db_ok else "unavailable", "database": db_ok}
