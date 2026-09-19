"""Coverage for codeguard.api.signature.is_valid_signature — the HMAC
check that decides whether an inbound webhook is really from GitHub.

This is the service's only authentication boundary, and it was the one
load-bearing function with no test of its own: tests/pipeline/
test_feedback_webhook.py deliberately calls _handle_feedback_comment
directly "rather than through a full HTTP+signature round trip", so
nothing exercised this function until now.

Each test below pins one of the guarantees the module's own docstring
claims, so that a refactor has to break a test rather than just a
comment.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from codeguard.api.signature import is_valid_signature

SECRET = "a-test-webhook-secret"
BODY = b'{"action":"opened","number":7}'


def _sign(secret: str, body: bytes) -> str:
    """Builds the header GitHub would send, independently of the
    implementation under test — recomputed here from hmac/hashlib
    directly rather than by calling into signature.py, so a bug in the
    production digest construction can't make these tests agree with it.
    """
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_a_correctly_signed_body_is_accepted():
    assert is_valid_signature(SECRET, BODY, _sign(SECRET, BODY)) is True


def test_a_signature_from_the_wrong_secret_is_rejected():
    """The attacker-controls-the-payload case: a well-formed sha256=
    header over the exact right bytes, signed with a key the sender
    doesn't have.
    """
    forged = _sign("not-the-real-secret", BODY)

    assert forged.startswith("sha256=")
    assert is_valid_signature(SECRET, BODY, forged) is False


@pytest.mark.parametrize("header", [None, ""])
def test_a_missing_header_is_rejected_and_never_raises(header):
    """"Fails closed": an absent header is treated exactly like a wrong
    signature. None is what FastAPI hands over when the header isn't
    present at all; "" is the empty-but-present case.
    """
    assert is_valid_signature(SECRET, BODY, header) is False


@pytest.mark.parametrize(
    "header",
    [
        "sha1=" + hmac.new(SECRET.encode(), BODY, hashlib.sha1).hexdigest(),  # right secret, wrong algorithm
        hmac.new(SECRET.encode(), BODY, hashlib.sha256).hexdigest(),          # right digest, no prefix
        "sha256=",                                                            # prefix, no digest
        "garbage",
    ],
)
def test_a_malformed_prefix_is_rejected(header):
    """A digest computed with the right secret is still rejected when it
    doesn't arrive as sha256=<hex> — the prefix check runs before any
    comparison, so a downgrade to sha1 never reaches compare_digest.
    """
    assert is_valid_signature(SECRET, BODY, header) is False
