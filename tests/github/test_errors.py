"""Tests rate-limit-aware backoff (extract_retry_after) against a
constructed rate-limit response — not just the generic
exponential-backoff path, which was the only one exercised live before.
"""

from __future__ import annotations

import time

import requests

from codeguard.github.errors import extract_retry_after
from codeguard.worker.main import RateLimited


def _response(headers: dict) -> requests.Response:
    resp = requests.Response()
    resp.headers.update(headers)
    return resp


def test_retry_after_header_used_directly():
    resp = _response({"Retry-After": "30"})
    assert extract_retry_after(resp) == 30.0


def test_rate_limit_reset_used_when_remaining_is_zero():
    reset_at = int(time.time()) + 60
    resp = _response({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset_at)})
    delay = extract_retry_after(resp)
    assert delay is not None
    assert 55 <= delay <= 61  # ~60s, allowing for test execution drift


def test_rate_limit_reset_in_the_past_floors_at_zero():
    resp = _response({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(time.time()) - 100)})
    assert extract_retry_after(resp) == 0.0


def test_remaining_nonzero_ignores_reset_header():
    resp = _response({"X-RateLimit-Remaining": "10", "X-RateLimit-Reset": "9999999999"})
    assert extract_retry_after(resp) is None


def test_no_rate_limit_signal_returns_none():
    assert extract_retry_after(_response({})) is None


def test_retry_after_takes_priority_over_rate_limit_reset():
    resp = _response({"Retry-After": "5", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "9999999999"})
    assert extract_retry_after(resp) == 5.0


def test_malformed_retry_after_falls_through_to_rate_limit_reset():
    reset_at = int(time.time()) + 20
    resp = _response({"Retry-After": "not-a-number", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(reset_at)})
    delay = extract_retry_after(resp)
    assert delay is not None
    assert 15 <= delay <= 21


def test_rate_limited_exception_carries_retry_after_through_to_nack():
    exc = RateLimited(12.5)
    assert exc.retry_after == 12.5
    assert "12.5" in str(exc)
