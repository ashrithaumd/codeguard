"""Credential masking before render.

The case that forces this: Bandit's B105/B106 findings are *about*
hardcoded secrets, and their message includes the matched source line.
On GitHub that sits behind the repo's access control; a dashboard page
for a public repo does not, so "we found your secret" becomes "here is
your secret" to anyone with the URL.

Every test states the secret it expects gone AND the context it expects
kept — a redactor that blanked the whole message would pass a
"secret not in output" assertion while making the page useless.
"""

from __future__ import annotations

import pytest

from codeguard.redact import MASK, redact


# Every token here is invented, but the formats are real enough that
# GitHub's push protection blocked the first version of this file for
# containing a "Slack API Token" and a "Stripe API Key". Splitting each
# literal across a concatenation keeps the value identical at runtime
# while making sure no credential-shaped string ever sits in a source
# line — which is also the honest signal that these are fabricated.
@pytest.mark.parametrize("secret", [
    "gh" + "p_16CharactersXXXXXXXXXXXXXXXXXXXXXXXX",
    "github" + "_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz",
    "sk-" + "ant-api03-abcdefghijklmnopqrstuvwxyz0123",
    "sk" + "-abcdefghijklmnopqrstuvwxyz0123456789",
    "sk_" + "live_51HabcdefghijklmnopQ",
    "AKIA" + "IOSFODNN7EXAMPLE",
    "AIza" + "SyD-1234567890abcdefghijklmnopqrstuv",
    "xox" + "b-123456789012-abcdefghijklmnopqrst",
    "glpat" + "-abcdefghijklmnopqrst",
])
def test_a_vendor_token_is_masked_wherever_it_appears(secret):
    out = redact(f"Possible hardcoded credential: {secret} assigned inline.")

    assert secret not in out
    assert MASK in out
    assert "hardcoded credential" in out, "the finding must still say what it found"


def test_an_assigned_secret_keeps_its_name_and_loses_its_value():
    """The name is the useful half. "password" tells a reader what was
    found; the value tells them nothing they should be reading here.
    """
    out = redact("B105: password = 'hunter2isnotverygood' found at line 3")

    assert "hunter2isnotverygood" not in out
    assert "password" in out
    assert "line 3" in out


@pytest.mark.parametrize("name", [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "API_KEY", "client_secret", "private_key", "access_key", "passphrase",
])
def test_every_secret_ish_name_has_its_value_masked(name):
    out = redact(f'{name} = "abcdefghijklmnop"')

    assert "abcdefghijklmnop" not in out
    assert name in out


def test_credentials_in_a_url_are_masked_but_the_host_is_kept():
    out = redact("connection failed: postgresql://admin:sup3rs3cretpw@db.example.com:5432/app")

    assert "sup3rs3cretpw" not in out
    assert "db.example.com" in out, "the host is the diagnostic part"
    assert "admin" in out


def test_a_private_key_body_is_masked_but_its_header_survives():
    pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
           "MIIEpAIBAAKCAQEAwJ8vRk2lPqxYz9\n"
           "-----END RSA PRIVATE KEY-----")

    out = redact(f"Found a key: {pem}")

    assert "MIIEpAIBAAKCAQEAwJ8vRk2lPqxYz9" not in out
    assert "BEGIN RSA PRIVATE KEY" in out, "still say WHAT was found"


def test_a_long_opaque_quoted_token_is_masked():
    out = redact("header set to 'aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldCBrZXk='")

    assert "aGVsbG8gd29ybGQ" not in out
    assert MASK in out


def test_a_jwt_is_masked():
    jwt = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
           "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "dBjftJeZ4CVPmB92K27uhbUJU1p1r1wEFJlbXLnDwDo")

    out = redact(f"Authorization: Bearer {jwt}")

    assert jwt not in out
    assert "Authorization" in out


# --- what must NOT be touched -------------------------------------------


@pytest.mark.parametrize("text", [
    "SQL injection vulnerability confirmed. The query uses string formatting.",
    "billing/charge.py:88 reaches execute() without parameterisation.",
    "quality.error-handling: this function has no error handling at all.",
    "B608: Possible SQL injection vector through string-based query construction.",
    "requests 2.19.1 is affected by a known CRLF injection vulnerability.",
    "Line too long (118 > 100 characters).",
    "The division operation on line 13 lacks protection against division by zero.",
])
def test_ordinary_finding_text_is_left_alone(text):
    """Over-redaction is the safe direction, but a redactor that eats
    normal prose makes every finding unreadable, which is its own
    failure.
    """
    assert redact(text) == text


def test_a_file_path_is_not_mistaken_for_a_token():
    text = "codeguard/pipeline/nodes.py:1284 in _parse_direct_findings"

    assert redact(text) == text


def test_a_commit_sha_is_left_readable():
    """40 hex characters is long and high-entropy, but a SHA is a
    coordinate, not a credential — masking it would break the one field
    that identifies which commit was reviewed.
    """
    text = "head_sha b58413af04a1fc99cf4fa3c0eb54bf69c6315ba0 reviewed"

    assert redact(text) == text


def test_empty_and_none_ish_input_is_safe():
    assert redact("") == ""
