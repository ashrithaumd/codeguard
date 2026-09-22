"""The bearer token on /metrics.

This endpoint was publicly reachable on the Container Apps ingress and
served repo names, job counts and cost to anyone who asked. It is
deliberately NOT behind EasyAuth — Prometheus is a machine client and
cannot follow a login redirect — so a token it can send as a header is
the only gate that works for it.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from codeguard.api.auth import require_metrics_token
from codeguard.config import Settings


def _request(auth: str | None = None) -> Request:
    headers = [(b"authorization", auth.encode())] if auth else []
    return Request({"type": "http", "method": "GET", "path": "/metrics",
                    "headers": headers, "query_string": b""})


def _with_token(token: str):
    return patch("codeguard.api.auth.get_settings",
                 return_value=Settings(anthropic_api_key="x", metrics_auth_token=token))


def test_no_configured_token_leaves_the_endpoint_open():
    """A deliberate fail-OPEN, and the only one in this codebase: local
    compose and the Prometheus container scrape without a token, and a
    missing env var must not break metrics collection everywhere at
    once. api/main.py warns loudly at startup instead.
    """
    with _with_token(""):
        require_metrics_token(_request())  # does not raise


def test_a_correct_token_is_accepted():
    with _with_token("s3cret"):
        require_metrics_token(_request("Bearer s3cret"))


@pytest.mark.parametrize("header", [
    None,
    "Bearer wrong",
    "Bearer ",
    "s3cret",             # no scheme
    "Basic s3cret",       # wrong scheme
    "Bearer s3cre",       # prefix of the real token
    "Bearer s3crett",     # superstring of the real token
])
def test_anything_other_than_the_exact_token_is_rejected(header):
    with _with_token("s3cret"):
        with pytest.raises(HTTPException) as exc:
            require_metrics_token(_request(header))
    assert exc.value.status_code == 401


def test_the_scheme_is_matched_case_insensitively():
    """RFC 7235 makes the scheme case-insensitive and real clients vary."""
    with _with_token("s3cret"):
        require_metrics_token(_request("bearer s3cret"))
        require_metrics_token(_request("BEARER s3cret"))


def test_no_www_authenticate_challenge_is_sent():
    """One non-interactive client, so a challenge would only prompt a
    browser for credentials that do not exist.
    """
    with _with_token("s3cret"):
        with pytest.raises(HTTPException) as exc:
            require_metrics_token(_request())
    assert not (exc.value.headers or {}).get("WWW-Authenticate")
