"""Only a public github.com repository URL may reach the worker.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
cli._is_remote_url is the only check today:

    target.startswith(("http://", "https://", "git@")) or target.endswith(".git")

A visitor supplies the target, so that accepts:

  * any host                 https://evil.example/payload
  * userinfo                 https://x-access-token:TOKEN@github.com/o/r
  * any port                 https://github.com:8080/o/r
  * path traversal           https://github.com/o/r/../../../etc
  * scp syntax               git@evil.example:o/r
  * file-ish targets         anything ending .git

and the raw string is then handed to `git clone`. The clone URL must be
BUILT from a strictly parsed owner and repo, never echoed.

Two further gates use the same parse, per the approved plan:
  * the repository must be PUBLIC -- a visitor must not make the App's
    installation token read a private repo on their behalf
  * the repository must be SMALL ENOUGH, checked from the `size` field of
    the same API response, BEFORE anything is cloned. Measuring the clone
    directory afterwards means a 5 GB repository is already on disk.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from codeguard.api.repo_url import (
    MAX_REPO_SIZE_KB,
    RepoRejected,
    parse_public_github_url,
    verify_public_and_sized,
)

@pytest.fixture(autouse=True)
def _installation_token(monkeypatch):
    """A token is always available unless a test says otherwise.

    Autouse here is safe in a way it would not be for a security gate:
    the token is PLUMBING, not the control. The controls are the
    private/404/size branches, and every one of them is asserted
    explicitly. The no-token path has its own test
    (test_no_token_available_fails_closed) which overrides this.
    """
    monkeypatch.setattr("codeguard.api.repo_url.audit_api_token",
                        lambda: "ghs_FIXTURE_TOKEN")


ACCEPTED = [
    ("https://github.com/psf/requests", ("psf", "requests")),
    ("https://github.com/psf/requests/", ("psf", "requests")),
    ("https://github.com/psf/requests.git", ("psf", "requests")),
    ("https://github.com/psf/requests.git/", ("psf", "requests")),
    ("  https://github.com/psf/requests  ", ("psf", "requests")),
    ("https://GitHub.com/psf/requests", ("psf", "requests")),
    ("https://github.com/a-b.c_d/e.f-g_h", ("a-b.c_d", "e.f-g_h")),
]

REJECTED = [
    ("http://github.com/o/r", "plain http"),
    ("https://evil.example/o/r", "another host"),
    ("https://github.com.evil.example/o/r", "suffix-confusion host"),
    ("https://raw.githubusercontent.com/o/r", "a different github host"),
    ("https://x-access-token:ghp_AAAA@github.com/o/r", "userinfo carrying a token"),
    ("https://user@github.com/o/r", "userinfo without a password"),
    ("https://github.com:8080/o/r", "explicit port"),
    ("https://github.com/o/r/tree/main", "extra path segments"),
    ("https://github.com/o/r/../../etc/passwd", "path traversal"),
    ("https://github.com/o", "no repository segment"),
    ("https://github.com/", "no path at all"),
    ("https://github.com/o/r?x=1", "query string"),
    ("https://github.com/o/r#frag", "fragment"),
    ("git@github.com:o/r.git", "scp syntax"),
    ("file:///etc/passwd", "file scheme"),
    ("https://github.com/./r", "dot as owner"),
    ("https://github.com/o/..", "dotdot as repo"),
    ("https://github.com//r", "empty owner"),
    ("https://github.com/o//", "empty repo"),
    ("", "empty string"),
    ("/app/.env", "a local path"),
]


@pytest.mark.parametrize("raw,expected", ACCEPTED)
def test_accepted_urls_parse_to_owner_and_repo(raw, expected):
    assert parse_public_github_url(raw) == expected


@pytest.mark.parametrize("raw,why", REJECTED)
def test_rejected_urls_raise(raw, why):
    with pytest.raises(RepoRejected):
        parse_public_github_url(raw)


def test_the_clone_url_is_rebuilt_not_echoed():
    """Even for an accepted input, the URL used must be constructed.

    `https://GitHub.com/psf/requests.git/` is accepted, but what reaches
    git must be the canonical form built from the parsed parts -- so a
    future accepted-but-odd input cannot smuggle anything through.
    """
    from codeguard.api.repo_url import clone_url

    owner, repo = parse_public_github_url("https://GitHub.com/psf/requests.git/")
    assert clone_url(owner, repo) == "https://github.com/psf/requests"


def _repo_api(**over):
    body = {"private": False, "size": 1000, "fork": False,
            "full_name": "psf/requests", "archived": False}
    body.update(over)
    return body


def _resp(status=200, body=None):
    class R:
        status_code = status

        def json(self):
            return body if body is not None else {}
    return R()


def test_a_public_repo_of_reasonable_size_is_accepted():
    with patch("codeguard.api.repo_url.requests.get", return_value=_resp(200, _repo_api())):
        info = verify_public_and_sized("psf", "requests")
    assert info["size"] == 1000


def test_a_private_repo_is_rejected():
    """A visitor must not make the App's installation token read a private
    repository on their behalf."""
    with patch("codeguard.api.repo_url.requests.get",
               return_value=_resp(200, _repo_api(private=True))):
        with pytest.raises(RepoRejected) as caught:
            verify_public_and_sized("acme", "secret")
    assert "public" in str(caught.value).lower()


def test_an_oversized_repo_is_rejected_before_any_clone():
    """Amendment 2. GitHub's own `size` (KB) is read from the call we are
    already making, so a 5 GB repository is refused before it is on disk.
    """
    with patch("codeguard.api.repo_url.requests.get",
               return_value=_resp(200, _repo_api(size=MAX_REPO_SIZE_KB + 1))):
        with pytest.raises(RepoRejected) as caught:
            verify_public_and_sized("big", "repo")
    assert "too large" in str(caught.value).lower()


def test_a_missing_repo_is_rejected_with_a_friendly_message():
    with patch("codeguard.api.repo_url.requests.get", return_value=_resp(404)):
        with pytest.raises(RepoRejected) as caught:
            verify_public_and_sized("no", "such")
    message = str(caught.value)
    assert "couldn't find" in message.lower() or "could not find" in message.lower()
    assert "404" not in message, "no internal detail in a user-facing message"


def test_an_api_error_is_rejected_rather_than_assumed_public():
    """Fail closed. A 500 or a rate limit is not an answer, so it must not
    be read as "public and small enough"."""
    with patch("codeguard.api.repo_url.requests.get", return_value=_resp(500)):
        with pytest.raises(RepoRejected):
            verify_public_and_sized("o", "r")


def test_a_network_failure_is_rejected_not_swallowed():
    with patch("codeguard.api.repo_url.requests.get", side_effect=OSError("no route")):
        with pytest.raises(RepoRejected):
            verify_public_and_sized("o", "r")


def test_the_rejection_message_never_contains_a_token():
    """RepoRejected text is rendered to the user, so it goes through the
    same redaction the audit path uses."""
    token = "ghp_" + "c" * 36
    with pytest.raises(RepoRejected) as caught:
        parse_public_github_url(f"https://{token}@github.com/o/r")
    assert token not in str(caught.value)


# --------------------------------------------------------------------------
# Correction 2: the check must be AUTHENTICATED.
#
# THE VULNERABILITY THIS REPRODUCES
# Unauthenticated GitHub API calls are limited to 60 PER HOUR PER IP, and
# every visitor shares the api's IP. After roughly 60 audits in an hour the
# gate starts refusing everything -- and because a rate-limited response
# was handled by the same branch as any other non-200, it refused with
# "we couldn't find a public repository at that URL": a misleading message
# that sends the user to check a URL that is perfectly fine.
#
# An installation token raises the limit to 5,000/hour. The probing concern
# the unauthenticated call was protecting against is handled instead by
# returning ONE IDENTICAL MESSAGE for `private: true` and for 404, so the
# response still reveals nothing about whether a private repo exists.
# --------------------------------------------------------------------------


def _resp_with_headers(status, body=None, headers=None):
    class R:
        status_code = status

        def __init__(self):
            self.headers = headers or {}

        def json(self):
            return body if body is not None else {}
    return R()


def test_the_check_uses_an_installation_token():
    """60/hour shared across all visitors is not a usable budget."""
    seen = {}

    def fake_get(url, headers=None, timeout=None):
        seen["auth"] = (headers or {}).get("Authorization", "")
        return _resp_with_headers(200, _repo_api())

    with patch("codeguard.api.repo_url.requests.get", side_effect=fake_get), \
         patch("codeguard.api.repo_url.audit_api_token", return_value="ghs_TESTTOKEN"):
        verify_public_and_sized("psf", "requests")

    assert seen["auth"].startswith("Bearer "), "the call must be authenticated"
    assert "ghs_TESTTOKEN" in seen["auth"]


def test_a_private_repo_and_a_missing_repo_give_the_SAME_message():
    """The probing defence, now that the call is authenticated.

    An installation token can see private repositories it is installed on,
    so `private: true` is a real answer rather than a 404 -- which means the
    two messages have to be made identical deliberately. If they differed,
    a visitor could tell "this private repo exists" from "nothing here".
    """
    with patch("codeguard.api.repo_url.audit_api_token", return_value="t"):
        with patch("codeguard.api.repo_url.requests.get",
                   return_value=_resp_with_headers(200, _repo_api(private=True))):
            with pytest.raises(RepoRejected) as private_err:
                verify_public_and_sized("acme", "secret")

        with patch("codeguard.api.repo_url.requests.get",
                   return_value=_resp_with_headers(404)):
            with pytest.raises(RepoRejected) as missing_err:
                verify_public_and_sized("no", "such")

    assert str(private_err.value) == str(missing_err.value), (
        "private and missing must be indistinguishable"
    )


def test_a_rate_limited_response_says_try_again_not_not_found():
    """403 with the rate-limit marker. Telling the user their URL is wrong
    when the truth is "we are throttled" sends them to fix nothing."""
    with patch("codeguard.api.repo_url.audit_api_token", return_value="t"), \
         patch("codeguard.api.repo_url.requests.get",
               return_value=_resp_with_headers(
                   403, {"message": "API rate limit exceeded"},
                   {"x-ratelimit-remaining": "0"})):
        with pytest.raises(RepoRejected) as caught:
            verify_public_and_sized("o", "r")

    message = str(caught.value).lower()
    assert "again" in message, "must invite a retry"
    assert "couldn't find" not in message and "could not find" not in message


def test_a_429_is_also_treated_as_rate_limiting():
    with patch("codeguard.api.repo_url.audit_api_token", return_value="t"), \
         patch("codeguard.api.repo_url.requests.get",
               return_value=_resp_with_headers(429, {"message": "Too Many Requests"})):
        with pytest.raises(RepoRejected) as caught:
            verify_public_and_sized("o", "r")

    assert "again" in str(caught.value).lower()


def test_a_403_that_is_not_rate_limiting_is_not_a_retry_invitation():
    """A genuine permission 403 is not "try again in a minute"."""
    with patch("codeguard.api.repo_url.audit_api_token", return_value="t"), \
         patch("codeguard.api.repo_url.requests.get",
               return_value=_resp_with_headers(403, {"message": "Forbidden"},
                                               {"x-ratelimit-remaining": "4999"})):
        with pytest.raises(RepoRejected):
            verify_public_and_sized("o", "r")


def test_no_token_available_fails_closed():
    """If we cannot authenticate we do not silently fall back to the
    60/hour unauthenticated path -- that is the bug, not the remedy."""
    with patch("codeguard.api.repo_url.audit_api_token", return_value=None):
        with pytest.raises(RepoRejected):
            verify_public_and_sized("o", "r")


def test_an_oversized_repo_is_still_rejected_when_authenticated():
    with patch("codeguard.api.repo_url.audit_api_token", return_value="t"), \
         patch("codeguard.api.repo_url.requests.get",
               return_value=_resp_with_headers(200, _repo_api(size=MAX_REPO_SIZE_KB + 1))):
        with pytest.raises(RepoRejected) as caught:
            verify_public_and_sized("big", "repo")

    assert "too large" in str(caught.value).lower()
