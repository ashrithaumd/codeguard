"""Who can see which review.

The failure this guards against is one-directional: showing a private
repo's findings to someone who should not see them cannot be undone,
while hiding something wrongly costs a login. Every test here asserts
the deny side as carefully as the allow side.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from codeguard.api import access
from codeguard.api.access import can_view, reset_caches, visible_private_repos


@pytest.fixture(autouse=True)
def _clear():
    reset_caches()
    yield
    reset_caches()


def _collab(answer: bool):
    return patch.object(access, "_is_collaborator", return_value=answer)


# --- the rule itself ----------------------------------------------------


def test_a_public_review_is_visible_to_anyone():
    assert can_view(owner="o", repo="r", private=False, principal=None)
    assert can_view(owner="o", repo="r", private=False, principal="someone")


def test_a_private_review_is_invisible_to_an_anonymous_visitor():
    assert not can_view(owner="o", repo="r", private=True, principal=None)


def test_an_anonymous_visitor_never_triggers_a_github_call():
    """The common case must stay free. A GitHub round trip per anonymous
    page view would also be a trivial way to burn the App's rate limit.
    """
    with patch.object(access, "_is_collaborator") as collab:
        assert not can_view(owner="o", repo="r", private=True, principal=None)
    collab.assert_not_called()


def test_a_private_review_is_visible_to_a_collaborator():
    with _collab(True):
        assert can_view(owner="o", repo="r", private=True, principal="alice")


def test_a_private_review_is_hidden_from_a_non_collaborator():
    with _collab(False):
        assert not can_view(owner="o", repo="r", private=True, principal="mallory")


# --- failure modes all deny ---------------------------------------------


def test_an_unanswerable_collaborator_check_denies():
    """A rate limit or a 5xx is not an answer, so it is not treated as
    one. GitHub returns 404 for a repo the caller cannot see, which IS
    an answer and is handled separately.
    """
    class Resp:
        status_code = 500

    with patch.object(access, "_installation_id", return_value=99), \
         patch.object(access, "get_installation_token", return_value="tok"), \
         patch.object(access.requests, "get", return_value=Resp()):
        assert not can_view(owner="o", repo="r", private=True, principal="alice")


def test_a_network_failure_denies_rather_than_raising():
    with patch.object(access, "_installation_id", return_value=99), \
         patch.object(access, "get_installation_token", return_value="tok"), \
         patch.object(access.requests, "get", side_effect=OSError("boom")):
        assert not can_view(owner="o", repo="r", private=True, principal="alice")


def test_a_repo_with_no_installation_denies():
    with patch.object(access, "_installation_id", return_value=None):
        assert not can_view(owner="o", repo="r", private=True, principal="alice")


def test_github_404_means_no_access_not_an_error():
    class Resp:
        status_code = 404

    with patch.object(access, "_installation_id", return_value=99), \
         patch.object(access, "get_installation_token", return_value="tok"), \
         patch.object(access.requests, "get", return_value=Resp()) as get:
        assert not can_view(owner="o", repo="r", private=True, principal="alice")
    assert get.called, "a 404 is GitHub's real answer, so it must actually be asked"


# --- caching ------------------------------------------------------------


def test_a_decision_is_cached_per_user_and_repo():
    with _collab(True) as collab:
        can_view(owner="o", repo="r", private=True, principal="alice")
        can_view(owner="o", repo="r", private=True, principal="alice")
    assert collab.call_count == 1


def test_one_users_access_is_not_another_users():
    """The cache key includes the principal. Sharing an entry across
    users would hand one user another's access.
    """
    def only_alice(owner, repo, username):
        return username == "alice"

    with patch.object(access, "_is_collaborator", side_effect=only_alice):
        assert can_view(owner="o", repo="r", private=True, principal="alice")
        assert not can_view(owner="o", repo="r", private=True, principal="mallory")


def test_access_is_not_shared_across_repos():
    def only_repo_a(owner, repo, username):
        return repo == "a"

    with patch.object(access, "_is_collaborator", side_effect=only_repo_a):
        assert can_view(owner="o", repo="a", private=True, principal="alice")
        assert not can_view(owner="o", repo="b", private=True, principal="alice")


# --- the listing filter -------------------------------------------------


def test_visible_private_repos_is_empty_for_anonymous():
    with patch.object(access, "_is_collaborator") as collab:
        assert visible_private_repos([("o", "a"), ("o", "b")], None) == []
    collab.assert_not_called()


def test_visible_private_repos_returns_only_the_permitted_ones():
    def only_a(owner, repo, username):
        return repo == "a"

    with patch.object(access, "_is_collaborator", side_effect=only_a):
        assert visible_private_repos([("o", "a"), ("o", "b")], "alice") == [("o", "a")]
