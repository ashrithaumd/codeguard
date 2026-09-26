"""Strict parsing and vetting of a visitor-supplied repository URL.

The only check before this module existed was cli._is_remote_url:

    target.startswith(("http://", "https://", "git@")) or target.endswith(".git")

which accepted any host, userinfo, any port, path traversal and scp
syntax, and then handed the RAW STRING to `git clone`. A visitor chooses
the target, so that is an arbitrary-URL fetch performed by the worker,
with the worker's network position and the worker's filesystem.

Two rules here, and they are deliberately separate functions:

    parse_public_github_url   is this a github.com repository URL at all,
                              and which owner/repo is it
    verify_public_and_sized   does GitHub say that repository is public
                              and small enough to audit

The first is pure and total -- no network, no I/O, safe to call on
anything. The second costs one API call and is the gate that must not be
skipped before queueing.

ALLOW-LIST, NOT DENY-LIST. Every rejected shape in the tests was rejected
because it failed to match the one accepted shape, not because someone
thought of it. A deny-list of "no userinfo, no ports, no traversal" is a
list of the tricks we happened to imagine.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import requests

from codeguard.api.access import audit_api_token
from codeguard.redact import redact

_API = "https://api.github.com"
_TIMEOUT = 10

# GitHub's own rules, tightened. GitHub allows owner and repo names from
# [A-Za-z0-9._-]; we additionally refuse names that are entirely dots,
# which is how `.` and `..` would arrive.
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")

# GitHub reports repository size in KILOBYTES. 250 MB is generous against
# the largest thing audited so far (langflow, ~847k lines) and small
# enough that a clone cannot fill the worker's disk. Checked from the API
# BEFORE cloning -- measuring the clone directory afterwards means the
# repository is already on disk, which is the cost we are trying to avoid.
MAX_REPO_SIZE_KB = 250_000


NOT_FOUND_MESSAGE = (
    "We couldn't find a public repository at that URL. "
    "CodeGuard can only audit public repositories."
)


def _is_rate_limited(resp) -> bool:
    """GitHub signals throttling as 403 with no remaining quota, or 429.

    A plain 403 is a permission problem and must NOT be reported as "try
    again in a minute", so the remaining-quota header is what distinguishes
    them rather than the status alone.
    """
    if resp.status_code == 429:
        return True
    if resp.status_code != 403:
        return False
    remaining = (getattr(resp, "headers", None) or {}).get("x-ratelimit-remaining")
    return remaining == "0"


class RepoRejected(Exception):
    """A user-facing refusal.

    The message is rendered to the person who asked, so it says what they
    can do about it and nothing about our internals -- no status codes, no
    paths, no exception classes. Passed through redact() on construction
    because the text can embed the input, and the input can contain a
    token (`https://ghp_.../o/r` is a shape people really type).
    """

    def __init__(self, message: str):
        super().__init__(redact(message))


def parse_public_github_url(raw: str) -> tuple[str, str]:
    """`https://github.com/{owner}/{repo}` -> (owner, repo), or raise.

    Total: every other input raises RepoRejected. Pure: no network.
    """
    candidate = (raw or "").strip()
    if not candidate:
        raise RepoRejected("Please paste a GitHub repository URL.")

    parts = urlsplit(candidate)

    if parts.scheme.lower() != "https":
        raise RepoRejected("The URL must start with https://.")
    # netloc rather than hostname, so userinfo and ports are visible.
    # hostname alone silently discards both, which is exactly how
    # `https://token@github.com/o/r` would look acceptable.
    if parts.netloc.lower() != "github.com":
        raise RepoRejected("Only github.com repository URLs are supported.")
    if parts.query or parts.fragment:
        raise RepoRejected("The URL must not contain a query string or fragment.")

    segments = [s for s in parts.path.split("/") if s]
    if len(segments) != 2:
        raise RepoRejected(
            "The URL should look like https://github.com/owner/repository."
        )

    owner, repo = segments
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]

    for segment in (owner, repo):
        if not _SEGMENT.match(segment) or set(segment) <= {"."}:
            raise RepoRejected(
                "The URL should look like https://github.com/owner/repository."
            )

    return owner, repo


def clone_url(owner: str, repo: str) -> str:
    """The URL git is given. BUILT, never the caller's string.

    The whole point of parsing is that nothing downstream sees the input,
    so an accepted-but-odd variant (`https://GitHub.com/o/r.git/`) cannot
    smuggle anything into the subprocess.
    """
    return f"https://github.com/{owner}/{repo}"


def verify_public_and_sized(owner: str, repo: str) -> dict:
    """Ask GitHub whether this repository may be audited. Fails closed.

    One call answers both gates, which is why they are checked together:

      private    a visitor must not make the App's installation token read
                 a private repository on their behalf
      size       refused here, BEFORE the clone, from GitHub's own figure

    AUTHENTICATED, with an installation token. The first version called
    GitHub anonymously, reasoning that an anonymous call cannot be used to
    probe for private repositories -- true, but unauthenticated GitHub
    allows 60 REQUESTS PER HOUR PER IP and every visitor shares the api's
    IP. After roughly 60 audits in an hour the gate refused everything,
    and refused with "we couldn't find a public repository at that URL":
    a message that sends the user to fix a URL that was never wrong. An
    installation token raises the limit to 5,000/hour.

    The probing concern moves here instead of being solved by staying
    anonymous: NOT_FOUND_MESSAGE is returned for `private: true` AND for
    404, identically, so the response reveals nothing about whether a
    private repository exists. An installation token CAN see private repos
    the App is installed on, so that identity has to be deliberate rather
    than incidental.

    Rate limiting is its own branch. "GitHub is busy, try again" and "that
    repository does not exist" are different instructions, and giving the
    second when the first is true wastes the user's time entirely.

    Anything else that is not a clear 200 is refused. "The lookup failed"
    has no safe default that means yes, and no token means refuse rather
    than quietly fall back to the 60/hour path.
    """
    token = audit_api_token()
    if not token:
        raise RepoRejected(
            "We couldn't check that repository just now. Please try again."
        )

    try:
        resp = requests.get(
            f"{_API}/repos/{owner}/{repo}",
            headers={"Accept": "application/vnd.github+json",
                     "Authorization": f"Bearer {token}"},
            timeout=_TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 - every transport failure is one refusal
        raise RepoRejected(
            "We couldn't reach GitHub to check that repository. Please try again."
        ) from exc

    if _is_rate_limited(resp):
        raise RepoRejected(
            "GitHub is busy right now. Please try again in a minute."
        )
    if resp.status_code == 404:
        raise RepoRejected(NOT_FOUND_MESSAGE)
    if resp.status_code != 200:
        raise RepoRejected(
            "We couldn't check that repository just now. Please try again."
        )

    try:
        info = resp.json()
    except ValueError as exc:
        raise RepoRejected(
            "We couldn't check that repository just now. Please try again."
        ) from exc

    if info.get("private", True):
        # IDENTICAL to the 404 message, deliberately. An installation token
        # can see private repositories the App is installed on, so without
        # this a visitor could tell "that private repo exists" from
        # "nothing there" by which refusal came back.
        raise RepoRejected(NOT_FOUND_MESSAGE)

    size_kb = info.get("size") or 0
    if size_kb > MAX_REPO_SIZE_KB:
        raise RepoRejected(
            f"This repository is too large to audit "
            f"({size_kb // 1024} MB; the limit is {MAX_REPO_SIZE_KB // 1024} MB)."
        )

    return info
