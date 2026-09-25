"""May this visitor see this review?

The rule, in full:

  public repo   -> anyone, signed in or not
  private repo  -> only a signed-in user GitHub says can access the repo

Authorization is DELEGATED to GitHub and never reimplemented here. We
store no allow-list, no roles, no copy of who can see what — any such
copy would go stale the moment someone is removed from a repo, and
would go stale silently. GitHub is asked, and GitHub's answer is used.

Visibility itself is NOT asked at render time: it is read from the
review row, recorded when the review ran (migrations/007). A live
lookup would fail for a repo that has since been deleted or had the App
uninstalled, and "the visibility lookup failed" is not a question with a
safe guess attached to it.

Every failure path denies. A denial costs a reviewer a login; a wrong
allow publishes a private repo's findings, file paths and source
fragments to anyone holding the URL.
"""

from __future__ import annotations

import logging
import time

import requests

from codeguard.github.auth import build_app_jwt, get_installation_token

logger = logging.getLogger(__name__)

_API = "https://api.github.com"
_TIMEOUT = 10

# Two caches with deliberately different lifetimes.
#
# An installation id changes only when the App is installed or removed
# from a repo, so it is cached for an hour; getting it wrong costs one
# failed lookup that then denies.
#
# An access decision is cached for 60s only. That is the window in
# which someone removed from a private repo can still load a page, and
# it is the price of not making a GitHub round trip per page view.
# Short enough to be a rounding error on a revocation, long enough that
# a reviewer clicking through a few reviews pays for one call.
#
# Correct because the api is pinned to a single replica (see
# api/main.py's reaper note). If it ever scales out, these become
# per-replica and the TTLs become per-replica too — still correct, just
# less effective.
_INSTALLATION_TTL = 3600
_DECISION_TTL = 60

_installation_cache: dict[tuple[str, str], tuple[float, int | None]] = {}
_decision_cache: dict[tuple[str, str, str], tuple[float, bool]] = {}


def _cached(cache: dict, key, ttl: int):
    entry = cache.get(key)
    if entry is None:
        return None
    stored_at, value = entry
    if time.monotonic() - stored_at > ttl:
        cache.pop(key, None)
        return None
    return (value,)


def _installation_id(owner: str, repo: str) -> int | None:
    """The App's installation on this repo, via an App JWT.

    Needed because get_installation_token is scoped to an installation
    and the review row does not carry one. Cached negatively too — a
    repo the App is not installed on should not cost a GitHub call per
    page view.
    """
    key = (owner, repo)
    hit = _cached(_installation_cache, key, _INSTALLATION_TTL)
    if hit is not None:
        return hit[0]

    try:
        resp = requests.get(
            f"{_API}/repos/{owner}/{repo}/installation",
            headers={"Authorization": f"Bearer {build_app_jwt()}",
                     "Accept": "application/vnd.github+json"},
            timeout=_TIMEOUT,
        )
        installation_id = resp.json()["id"] if resp.status_code == 200 else None
    except Exception:
        # Not cached: a transient network failure should be retried on
        # the next request, not remembered for an hour as "no access".
        logger.warning("installation lookup failed for %s/%s", owner, repo, exc_info=True)
        return None

    _installation_cache[key] = (time.monotonic(), installation_id)
    return installation_id


def _is_collaborator(owner: str, repo: str, username: str) -> bool:
    """GitHub's own answer to "can this user access this repo".

    204 means yes, 404 means no — GitHub deliberately answers 404 rather
    than 403 for a repo the caller cannot see, so a 404 here is a real
    answer and not an error to retry.

    Uses the App's installation token rather than the visitor's own
    OAuth token, which would require EasyAuth's token store and the blob
    storage that comes with it. The App can see the repo's collaborator
    list; asking it about a specific username gives the same answer for
    the case this gates.
    """
    installation_id = _installation_id(owner, repo)
    if installation_id is None:
        return False

    try:
        resp = requests.get(
            f"{_API}/repos/{owner}/{repo}/collaborators/{username}",
            headers={"Authorization": f"Bearer {get_installation_token(installation_id)}",
                     "Accept": "application/vnd.github+json"},
            timeout=_TIMEOUT,
        )
    except Exception:
        logger.warning("collaborator check failed for %s/%s/%s", owner, repo, username, exc_info=True)
        return False

    if resp.status_code == 204:
        return True
    if resp.status_code == 404:
        return False
    # Anything else (rate limit, 5xx, a token that lost its scope) is
    # not an answer, so it is not treated as one.
    logger.warning(
        "collaborator check for %s/%s/%s returned %s; denying",
        owner, repo, username, resp.status_code,
    )
    return False


def can_view(*, owner: str, repo: str, private: bool, principal: str | None) -> bool:
    """The whole access rule. `private` comes from the review row."""
    if not private:
        return True
    if not principal:
        return False

    key = (owner, repo, principal)
    hit = _cached(_decision_cache, key, _DECISION_TTL)
    if hit is not None:
        return hit[0]

    allowed = _is_collaborator(owner, repo, principal)
    _decision_cache[key] = (time.monotonic(), allowed)
    return allowed


def reset_caches() -> None:
    """For tests, and for a future admin endpoint that needs to make a
    revocation take effect immediately rather than within _DECISION_TTL.
    """
    _installation_cache.clear()
    _installed_cache.clear()
    _decision_cache.clear()


def visible_private_repos(
    candidates: list[tuple[str, str]], principal: str | None,
) -> list[tuple[str, str]]:
    """Which of these private repos this visitor may see.

    Short-circuits to nothing for an anonymous visitor so an unauthenticated
    page view makes no GitHub calls at all — the common case, and the one
    that must stay cheap.
    """
    if not principal:
        return []
    return [
        (owner, repo) for owner, repo in candidates
        if can_view(owner=owner, repo=repo, private=True, principal=principal)
    ]


# ---------------------------------------------------------------------------
# Which repositories CodeGuard is installed on.
#
# Separate from the can_view machinery above and deliberately NOT an
# authorization input. This answers "is CodeGuard active here", which is
# a fact about the App; can_view answers "may this person see it", which
# is a fact about the person. The repositories page needs both and ANDs
# them -- an installed private repo is still invisible to someone GitHub
# says cannot access it.
# ---------------------------------------------------------------------------

# Installations change only when someone installs, uninstalls, or edits
# the repository selection on github.com. An hour matches
# _INSTALLATION_TTL above for the same reason: the cost of being stale
# is a row that is briefly wrong on one page, and the "Manage on GitHub"
# link is right there to correct it.
_INSTALLED_TTL = 3600
_installed_cache: dict[str, tuple[float, list[dict] | None]] = {}


class InstallationLookupFailed(Exception):
    """GitHub could not be asked. Distinct from "asked, and the answer is
    none": the repositories page renders those two differently, because
    an empty list means "you have not installed CodeGuard anywhere" and
    a failure means "we do not know", and telling a user the first when
    the second is true sends them to go and re-install something that is
    already installed.
    """


def _app_installations() -> list[dict]:
    """Every installation of this App, via an App JWT.

    GitHub has no single endpoint for "every repo across every
    installation" -- /installation/repositories is scoped to one
    installation token -- so this is the first of the two calls.
    """
    resp = requests.get(
        f"{_API}/app/installations",
        headers={"Authorization": f"Bearer {build_app_jwt()}",
                 "Accept": "application/vnd.github+json"},
        params={"per_page": 100},
        timeout=_TIMEOUT,
    )
    if resp.status_code != 200:
        raise InstallationLookupFailed(f"/app/installations returned {resp.status_code}")
    return resp.json()


def _installation_repositories(installation_id: int) -> list[dict]:
    """The repos one installation covers.

    Paginated at 100. Deliberately capped at 10 pages: this feeds a page
    that makes a visibility call per repo, so an installation with
    thousands of repos would turn one page view into thousands of GitHub
    calls. Hitting the cap means the page is incomplete, which is
    visible to the user, rather than slow enough to time out, which is
    not.
    """
    repos: list[dict] = []
    for page in range(1, 11):
        resp = requests.get(
            f"{_API}/installation/repositories",
            headers={"Authorization": f"Bearer {get_installation_token(installation_id)}",
                     "Accept": "application/vnd.github+json"},
            params={"per_page": 100, "page": page},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            raise InstallationLookupFailed(
                f"/installation/repositories returned {resp.status_code}"
            )
        batch = resp.json().get("repositories", [])
        repos.extend(batch)
        if len(batch) < 100:
            break
    return repos


def installed_repositories() -> list[dict]:
    """Every repo CodeGuard is installed on, as
    [{owner, repo, private, installation_id, html_url}].

    UNFILTERED by visibility, and that is a hazard worth naming: this
    list contains PRIVATE repository names, and /installation/repositories
    returns them because the App can see them, not because the viewer
    can. Callers must run every entry through can_view before it reaches
    a template. Nothing in this function can enforce that, so it is
    stated here and again at the call site.

    Raises InstallationLookupFailed rather than returning [] when GitHub
    cannot be reached, so the caller can distinguish "none" from
    "unknown" and fail closed on the second.
    """
    hit = _cached(_installed_cache, "all", _INSTALLED_TTL)
    if hit is not None:
        if hit[0] is None:
            raise InstallationLookupFailed("cached failure")
        return hit[0]

    try:
        repos: list[dict] = []
        for installation in _app_installations():
            installation_id = installation["id"]
            for entry in _installation_repositories(installation_id):
                owner, _, name = entry["full_name"].partition("/")
                repos.append({
                    "owner": owner,
                    "repo": name,
                    "private": bool(entry.get("private", True)),
                    "installation_id": installation_id,
                    "html_url": entry.get("html_url", ""),
                })
    except InstallationLookupFailed:
        # Not cached. A transient failure should be retried on the next
        # page view, not remembered for an hour -- same reasoning as
        # _installation_id's bare `return None` above.
        logger.warning("installed-repository lookup failed", exc_info=True)
        raise
    except Exception as exc:
        logger.warning("installed-repository lookup failed", exc_info=True)
        raise InstallationLookupFailed(str(exc)) from exc

    _installed_cache["all"] = (time.monotonic(), repos)
    return repos


def installation_settings_url(installation_id: int | None) -> str:
    """Where a user goes to connect or disconnect a repository.

    GitHub's own installation settings page is the on/off switch and is
    not reimplemented here: it is the only place that can actually grant
    or revoke the App's access, it already handles org approval flows and
    repository pickers, and a local copy would be a permissions UI whose
    state could disagree with the real one.
    """
    if installation_id is None:
        return "https://github.com/settings/installations"
    return f"https://github.com/settings/installations/{installation_id}"
