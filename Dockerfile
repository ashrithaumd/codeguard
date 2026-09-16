FROM python:3.12-slim

WORKDIR /app

# Install curl for the health check
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY codeguard/ ./codeguard/
RUN pip install --no-cache-dir -e .

COPY . .

# 8000: api's uvicorn (webhook receiver + /health + /metrics).
# 9000: worker's own metrics server (see codeguard/worker/main.py) —
# only relevant when this image runs as the worker service
# (docker-compose.yml / the Azure worker Container App override the
# command below and expose 9000 instead).
EXPOSE 8000 9000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl --fail http://localhost:8000/health || exit 1

# Default: the api service. docker-compose.yml and the Azure worker
# Container App both override this command to run
# `python -m codeguard.worker.main` instead — this image is shared by
# both services, same as before Phase 10, only the default target changed
# from v1's Streamlit UI to v2's actual production entrypoint.
CMD ["uvicorn", "codeguard.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
