"""An audit belongs to the person who asked for it.

TWO DEFECTS THIS REPRODUCES, both of which are the same missing rule seen
from different sides.

1. THE GATE DOES NOT MATCH ITS OWN DOCUMENTED PREMISE.
   _audit_or_404 authorizes on can_access_repo -- "may you see this
   repository" -- while trigger_audit's AuditInFlightOther branch was
   written on the opposite premise, and says so:

       # SOMEONE ELSE's audit. Must NOT redirect: an audit is visible
       # only to its requester, so the id alone would be a working URL
       # to another person's result.

   It is not visible only to its requester. Anyone who can see the
   repository can open anyone's audit, so the 409 that so carefully
   carries no row is guarding a door that is open. Today every requester
   is the operator, so nothing leaks yet -- but Stage 2 lets visitors
   audit arbitrary PUBLIC repositories, where can_access_repo is true for
   every signed-in visitor. The rule has to be right before that ships,
   not after.

   The rule: an audit is visible to its requester, or to an operator (a
   principal on the audit allow-list). The operator pays for every audit
   and is the person who has to diagnose a failed one, so locking them
   out of a visitor's audit would make the facility unsupportable.

2. THE REPOSITORIES PAGE SHOWS EVERY REQUESTER'S AUDITS.
   latest_per_repo() is unscoped, so each row displays whoever audited it
   last -- their audit id, as a link, and its status. That discloses
   another person's activity, and it is the same leak as (1) reached
   through the page instead of the URL.

AND ONE PIECE OF MISSING WIRING. A viewer may have ONE audit in flight at
a time (audits_one_in_flight_per_user, migration 010). Nothing on the page
reflects that: every other repo still offers a live "Run audit" button,
and clicking it silently redirects to the audit already running on a
different repository. Not harmful -- the constraint holds and no second
job is queued -- but it reads as a broken button, and a button that does
something other than what it says is how people stop trusting a page.
"""

from __future__ import annotations

from unittest.mock import patch


from codeguard.api import access, audits as audits_mod
from tests.api.conftest import TEST_PRINCIPAL

OWNER = "ashrithaumd"
PUBLIC = "codeguard-playground"
OTHER = "second-repo"

OPERATOR = TEST_PRINCIPAL
SOMEONE_ELSE = "a-different-visitor"


def _installed(*names):
    return [
        {"owner": OWNER, "repo": name, "private": False,
         "installation_id": 4934663,
         "html_url": f"https://github.com/{OWNER}/{name}"}
        for name in (names or (PUBLIC,))
    ]


# as_principal now lives in tests/api/conftest.py. It was duplicated in
# three files, and the operator allow-list moving to numeric GitHub ids
# meant all three needed the same login -> id mapping -- three copies of
# which is three chances for one file to mean "the operator" while
# another means somebody else.


async def _audit_by(pool, requested_by, repo=PUBLIC, status=None):
    audit = await audits_mod.request_audit(
        pool, owner=OWNER, repo=repo, requested_by=requested_by, private=False,
    )
    if status:
        await audits_mod.finish_audit(
            pool, audit["id"], status=status, report_markdown="# REPORT-BODY-MARKER",
        )
    return audit


# --------------------------------------------------------------------------
# 1. The gate
# --------------------------------------------------------------------------


async def test_another_persons_audit_is_404(client, pool, as_principal):
    """The regression. Repo access is not audit access."""
    as_principal(OPERATOR)  # signed in, not an operator: no allow-list
    audit = await _audit_by(pool, SOMEONE_ELSE, status="done")

    with patch.object(access, "_is_collaborator", return_value=True):
        page = client.get(f"/dashboard/audits/{audit['id']}")
        poll = client.get(f"/dashboard/audits/{audit['id']}.json")

    assert page.status_code == 404
    assert poll.status_code == 404
    assert "REPORT-BODY-MARKER" not in page.text


async def test_my_own_audit_is_visible(client, pool, as_principal):
    as_principal(OPERATOR)
    audit = await _audit_by(pool, OPERATOR, status="done")

    with patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get(f"/dashboard/audits/{audit['id']}")

    assert resp.status_code == 200
    assert "REPORT-BODY-MARKER" in resp.text


async def test_an_operator_can_see_a_visitors_audit(client, pool, as_principal):
    """Deliberate, and the reason is money: the operator pays for every
    audit and is the one who has to diagnose a failed one. A rule that
    locked them out of a visitor's audit would make the facility
    unsupportable."""
    as_principal(OPERATOR, audit_principals=OPERATOR)
    audit = await _audit_by(pool, SOMEONE_ELSE, status="failed")

    with patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get(f"/dashboard/audits/{audit['id']}")

    assert resp.status_code == 200


async def test_repo_access_is_still_required_on_top(client, pool, as_principal):
    """Ownership is added to the repo check, not substituted for it. My own
    audit of a repo I have since lost access to must not remain readable
    -- the report quotes that repository's source."""
    as_principal(OPERATOR, audit_principals=OPERATOR)
    audit = await _audit_by(pool, OPERATOR, status="done")

    with patch.object(access, "_is_collaborator", return_value=False):
        resp = client.get(f"/dashboard/audits/{audit['id']}")

    assert resp.status_code == 404


async def test_the_404_is_the_same_for_missing_and_not_mine(client, pool, as_principal):
    """The conflation the rest of this module maintains: a distinguishable
    response would let someone confirm that a given repo is being
    audited."""
    import uuid

    as_principal(OPERATOR)
    audit = await _audit_by(pool, SOMEONE_ELSE, status="done")
    missing_id = uuid.uuid4()

    with patch.object(access, "_is_collaborator", return_value=True):
        mine_not = client.get(f"/dashboard/audits/{audit['id']}")
        missing = client.get(f"/dashboard/audits/{missing_id}")

    assert mine_not.status_code == missing.status_code == 404
    # Bodies too, not just the status. Compared with each response's own
    # noise removed: the id the caller supplied (it comes back in the
    # sign-in link) and the per-response CSP nonce.
    import re

    def _normalise(body, own_id):
        body = re.sub(r'nonce="[^"]*"', 'nonce="N"', body)
        return body.replace(str(own_id), "ID")

    assert _normalise(mine_not.text, audit["id"]) == _normalise(missing.text, missing_id)


# --------------------------------------------------------------------------
# 2. The page
# --------------------------------------------------------------------------


async def test_the_page_does_not_show_another_persons_audit(
    client, pool, as_principal,
):
    """latest_per_repo was unscoped, so the row displayed whoever audited
    it last -- id, link and status."""
    as_principal(OPERATOR, audit_principals=OPERATOR)
    audit = await _audit_by(pool, SOMEONE_ELSE, status="done")

    with patch.object(access, "installed_repositories", return_value=_installed()), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    assert resp.status_code == 200
    assert str(audit["id"]) not in resp.text, "another person's audit id is on the page"
    assert SOMEONE_ELSE not in resp.text


async def test_the_page_shows_my_own_audit(client, pool, as_principal):
    """The other direction, so the scoping cannot pass by showing nothing."""
    as_principal(OPERATOR, audit_principals=OPERATOR)
    audit = await _audit_by(pool, OPERATOR, status="done")

    with patch.object(access, "installed_repositories", return_value=_installed()), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    assert str(audit["id"]) in resp.text


# --------------------------------------------------------------------------
# 3. The in-flight wiring
# --------------------------------------------------------------------------


async def test_a_second_repo_offers_no_button_while_mine_is_running(
    client, pool, as_principal,
):
    """One audit per person in flight, so the page must say so rather than
    drawing a button whose click goes somewhere else."""
    as_principal(OPERATOR, audit_principals=OPERATOR)
    mine = await _audit_by(pool, OPERATOR, repo=PUBLIC)  # left queued

    with patch.object(access, "installed_repositories",
                      return_value=_installed(PUBLIC, OTHER)), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    assert resp.status_code == 200
    assert OTHER in resp.text, "the other repo's row must still be listed"
    # One form on the page at most -- and not for the other repo.
    assert f'action="/dashboard/repos/{OWNER}/{OTHER}/audit"' not in resp.text
    # And it points at the audit that is actually running.
    assert str(mine["id"]) in resp.text


async def test_every_button_returns_once_my_audit_finishes(
    client, pool, as_principal,
):
    """The lock has to release in the UI as well as in the index."""
    as_principal(OPERATOR, audit_principals=OPERATOR)
    mine = await _audit_by(pool, OPERATOR, repo=PUBLIC)
    await audits_mod.finish_audit(pool, mine["id"], status="done", report_markdown="# ok")

    with patch.object(access, "installed_repositories",
                      return_value=_installed(PUBLIC, OTHER)), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    assert f'action="/dashboard/repos/{OWNER}/{OTHER}/audit"' in resp.text
    assert f'action="/dashboard/repos/{OWNER}/{PUBLIC}/audit"' in resp.text


async def test_someone_elses_in_flight_audit_does_not_disable_my_button(
    client, pool, as_principal,
):
    """The per-USER limit is per user. Another person's running audit
    constrains that repo (the per-repo index), not my access to every
    other one -- otherwise one visitor could freeze the page for
    everybody."""
    as_principal(OPERATOR, audit_principals=OPERATOR)
    await _audit_by(pool, SOMEONE_ELSE, repo=PUBLIC)  # theirs, queued

    with patch.object(access, "installed_repositories",
                      return_value=_installed(PUBLIC, OTHER)), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/repos")

    assert f'action="/dashboard/repos/{OWNER}/{OTHER}/audit"' in resp.text


# --------------------------------------------------------------------------
# 4. Identity: the display name must not buy anything, end to end
# --------------------------------------------------------------------------


async def test_a_stranger_named_after_the_operator_gets_no_button(
    client, pool, as_principal,
):
    """The route-level version of the identity regression.

    A visitor whose GitHub DISPLAY NAME is the operator's login. Before the
    fix the dashboard identified people by that display name, so this
    visitor WAS the operator as far as every gate could tell. Now the login
    decides repo access and the immutable numeric id decides operator
    rights, and a display name buys neither.

    Driven through the page rather than the helper, because the helper being
    right is not the same as the page using it.
    """
    from codeguard.api.auth import Viewer

    # Their own login and id; the operator's login as their display name.
    impostor = Viewer(login=SOMEONE_ELSE, user_id="900000001", display_name=OPERATOR)
    as_principal(OPERATOR, audit_principals=OPERATOR)  # the real operator is allowed

    with patch.object(access, "installed_repositories", return_value=_installed()), \
         patch.object(access, "_is_collaborator", return_value=True), \
         patch("codeguard.api.routes.dashboard.client_viewer", return_value=impostor), \
         patch("codeguard.api.routes.dashboard.client_principal",
               return_value=impostor.login):
        page = client.get("/dashboard/repos")
        posted = client.post(
            f"/dashboard/repos/{OWNER}/{PUBLIC}/audit", follow_redirects=False,
        )

    assert page.status_code == 200
    assert f'action="/dashboard/repos/{OWNER}/{PUBLIC}/audit"' not in page.text, (
        "a display name matching the operator's login drew an audit button"
    )
    # 404, not 403: this route hides its own existence from anyone who may
    # not audit, and CSRF is checked only after that.
    assert posted.status_code == 404
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT count(*) AS n FROM audits")
        assert (await cur.fetchone())["n"] == 0


async def test_the_nav_shows_the_display_name_while_decisions_use_the_login(
    client, pool, as_principal,
):
    """The display name keeps exactly one job. It appears in the nav, and the
    login is what the page gated on — visible here as the row the login can
    see."""
    from codeguard.api.auth import Viewer

    viewer = Viewer(login=OPERATOR, user_id="900000002", display_name="Ashritha Pola")
    as_principal(OPERATOR)

    with patch.object(access, "installed_repositories", return_value=_installed()), \
         patch.object(access, "_is_collaborator", return_value=True), \
         patch("codeguard.api.routes.dashboard.client_viewer", return_value=viewer), \
         patch("codeguard.api.routes.dashboard.client_principal", return_value=OPERATOR):
        resp = client.get("/dashboard/repos")

    assert "Ashritha Pola" in resp.text, "the nav does not show the display name"
    assert f"{OWNER}/{PUBLIC}" in resp.text, "the login did not gate the row in"
