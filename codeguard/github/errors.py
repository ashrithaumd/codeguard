"""Extracts a retry delay from a GitHub API rate-limit response, so a
worker can pass an explicit delay to nack() instead of trusting generic
exponential backoff to happen to be long enough — a real gap identified
in the Phase 1 review (the generic backoff path was never tested against
an actual rate-limit response).

GitHub signals rate limiting two ways:
  - Secondary rate limit / abuse detection: a `Retry-After` header with
    a plain number of seconds to wait. Most direct — use it verbatim.
  - Primary rate limit exhausted: `X-RateLimit-Remaining: 0` plus an
    `X-RateLimit-Reset` header (a Unix timestamp for when it resets).
    Compute the delay as reset_time - now, floored at 0.
"""

from __future__ import annotations

import time

import requests


def extract_retry_after(response: requests.Response) -> float | None:
    retry_after = response.headers.get("Retry-After")
    if retry_after is not None:
        try:
            return float(retry_after)
        except ValueError:
            pass

    remaining = response.headers.get("X-RateLimit-Remaining")
    reset_at = response.headers.get("X-RateLimit-Reset")
    if remaining == "0" and reset_at is not None:
        try:
            return max(0.0, float(reset_at) - time.time())
        except ValueError:
            pass

    return None
