from fastapi import FastAPI

from codeguard.api.routes.health import router as health_router

app = FastAPI(title="CodeGuard API")
app.include_router(health_router)
