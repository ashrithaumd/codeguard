FROM python:3.12-slim

WORKDIR /app

# curl: the health check. git: codeguard/mcp/server.py shells out to it
# for every local-diff ingestion (_run_git), so it is a real runtime
# dependency of the shipped image, not a test-only one -- without it that
# whole MCP path raises GitError("git is not installed or not on PATH").
RUN apt-get update && apt-get install -y --no-install-recommends curl git \
    && rm -rf /var/lib/apt/lists/*

# Dev extras (pytest, pytest-asyncio) are opt-in at build time rather
# than always-on: this same image is the production api and worker in
# Azure, and a test runner has no business in it there. docker-compose
# sets INSTALL_DEV=true so a clean clone gets a container that can
# actually run the suite -- the deterministic tool runners (semgrep,
# bandit, ruff) are real dependencies and live in the image either way,
# which is precisely why running the tests HERE and not on the host is
# the route that works on every platform.
ARG INSTALL_DEV=false

COPY pyproject.toml ./
COPY codeguard/ ./codeguard/
RUN if [ "$INSTALL_DEV" = "true" ]; then \
        pip install --no-cache-dir -e ".[dev]"; \
    else \
        pip install --no-cache-dir -e .; \
    fi

COPY . .

# Drop root. An audit clones a repository somebody else wrote and hands it
# to three parsers -- Bandit, Semgrep and Ruff -- each of which reads
# attacker-authored files in this container's own process tree. Root was
# buying nothing: the audit reads files, runs scanners that read files, and
# writes one report.
#
# /app is deliberately NOT chowned. It stays root-owned and read-only to
# this user, so a process reviewing untrusted code cannot modify the code
# reviewing it. Python skips writing __pycache__ silently when it cannot,
# and PYTHONDONTWRITEBYTECODE stops it trying.
#
# What the user DOES own is a home directory, because several things want
# one and are not graceful without it: Semgrep caches under $HOME, and
# tiktoken caches its downloaded encoding. A non-root image that forgets
# this works right up until the first real audit, then fails on a
# permissions error that reads like a code bug.
#
# Clones go to $TMPDIR (tempfile.mkdtemp), which is world-writable /tmp.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 codeguard \
    && chown -R codeguard:codeguard /home/codeguard
ENV HOME=/home/codeguard \
    PYTHONDONTWRITEBYTECODE=1
USER codeguard

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
