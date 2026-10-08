"""Dashboard bugs found checking feat/tour-fixes on localhost.

  1. The repo page 404'd for any repository with no PR review -- an
     installed, accessible repo with two audits read "Not found". The route
     treated "no review rows" as "no repository" before it ever asked
     whether the viewer may see it. Present on main too (a775557).
  2. The 404 copy said "This review..." / "Back to reviews" on every route.
  3. "last: done" under Run audit was a link styled as plain text.
  4. Timestamps were UTC with no label.
  5. The "recorded per delivery" footer was on every page.
  7. GET / was a 404.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

from codeguard.api import access
from tests.api.conftest import insert_review
from tests.api.test_repositories_activity import _insert_audit
from tests.api.test_security_headers import _CSP_BEFORE_CACHE_CONTROL, _csp

OWNER = "ashrithaumd"
REPO = "codeguard-playground"
VIEWER = "ashrithaumd"
OTHER = "someone-else"


def _repo_page(client, repo=REPO, collaborator=True):
    with patch.object(access, "_is_collaborator", return_value=collaborator):
        return client.get(f"/dashboard/repos/{OWNER}/{repo}")


# --------------------------------------------------------------------------
# 1. The repo page
# --------------------------------------------------------------------------

async def test_a_repo_with_only_audits_renders_and_lists_them(client, pool, as_principal):
    a1 = await _insert_audit(pool, cost=0.0347)
    a2 = await _insert_audit(pool, status="failed", cost=0.01)
    as_principal(VIEWER)
    resp = _repo_page(client)

    assert resp.status_code == 200
    audits = resp.text[resp.text.index("<h2>Audits</h2>"):]
    assert f'href="/dashboard/audits/{a1}"' in audits
    assert f'href="/dashboard/audits/{a2}"' in audits
    assert "No reviews yet" in resp.text


async def test_an_installed_repo_with_no_activity_renders_an_empty_state(client, pool, as_principal):
    as_principal(VIEWER)
    resp = _repo_page(client, repo="mealforge")

    assert resp.status_code == 200
    assert "No reviews yet" in resp.text
    assert "No audits yet" in resp.text


async def test_a_repo_the_viewer_cannot_access_still_404s(client, pool, as_principal):
    await _insert_audit(pool)
    await insert_review(pool, owner=OWNER, repo=REPO, private=False)
    as_principal(VIEWER)
    assert _repo_page(client, collaborator=False).status_code == 404


async def test_an_anonymous_visitor_gets_a_404(anon_client, pool):
    await insert_review(pool, owner=OWNER, repo=REPO, private=False)
    assert anon_client.get(f"/dashboard/repos/{OWNER}/{REPO}").status_code == 404


async def test_another_viewers_audits_never_appear(client, pool, as_principal):
    theirs = await _insert_audit(pool, requested_by=OTHER, cost=0.5)
    mine = await _insert_audit(pool, requested_by=VIEWER)
    as_principal(VIEWER)
    text = _repo_page(client).text

    assert str(mine) in text
    assert str(theirs) not in text
    assert "$0.5000" not in text


async def test_a_repo_with_reviews_still_lists_them(client, pool, as_principal):
    await insert_review(pool, owner=OWNER, repo=REPO, private=False, pr_number=5, pr_title="Add retry")
    as_principal(VIEWER)
    text = _repo_page(client).text
    assert "Add retry" in text and "No reviews yet" not in text


# --------------------------------------------------------------------------
# 2. 404 copy follows the route
# --------------------------------------------------------------------------

def _not_found(client, url):
    with patch.object(access, "_is_collaborator", return_value=False):
        resp = client.get(url)
    assert resp.status_code == 404
    return resp.text


async def test_a_missing_repository_says_repository(client, pool):
    text = _not_found(client, f"/dashboard/repos/{OWNER}/nope")
    assert "This repository either does not exist or is not visible to you" in text
    assert re.search(r'href="/dashboard/repos"[^>]*>Back to repositories<', text)
    assert "This review" not in text


async def test_a_missing_pull_request_says_pull_request(client, pool):
    text = _not_found(client, f"/dashboard/repos/{OWNER}/nope/pulls/3")
    assert "This pull request either does not exist" in text
    assert re.search(r'href="/dashboard/repos"[^>]*>Back to repositories<', text)


async def test_a_missing_audit_says_audit(client, pool):
    text = _not_found(client, f"/dashboard/audits/{uuid.uuid4()}")
    assert "This audit either does not exist" in text
    assert re.search(r'href="/dashboard/repos"[^>]*>Back to repositories<', text)


async def test_a_missing_review_says_review(client, pool):
    text = _not_found(client, f"/dashboard/reviews/{uuid.uuid4()}")
    assert "This review either does not exist" in text
    assert re.search(r'href="/dashboard"[^>]*>Back to reviews<', text)


# --------------------------------------------------------------------------
# 3. "last: done" is a link that looks like one
# --------------------------------------------------------------------------

async def test_last_audit_status_links_to_the_audit(client, pool, as_principal):
    audit_id = await _insert_audit(pool)
    as_principal(VIEWER, audit_principals=VIEWER)
    installed = [{"owner": OWNER, "repo": REPO, "private": False, "installation_id": 1,
                  "html_url": f"https://github.com/{OWNER}/{REPO}"}]
    with patch.object(access, "installed_repositories", return_value=installed), \
         patch.object(access, "_is_collaborator", return_value=True):
        text = client.get("/dashboard/repos").text

    assert re.search(
        rf'<a class="last-audit link" href="/dashboard/audits/{audit_id}"[^>]*>\s*last: done\s*</a>', text)


# --------------------------------------------------------------------------
# 4. Local time, from a labelled UTC fallback
# --------------------------------------------------------------------------

async def test_timestamps_are_time_elements_in_utc_with_a_label(client, pool, as_principal):
    when = datetime(2026, 10, 8, 16, 39, tzinfo=timezone.utc)
    await insert_review(pool, owner=OWNER, repo=REPO, private=False, created_at=when)
    as_principal(VIEWER)
    resp = _repo_page(client)

    assert '<time datetime="2026-10-08T16:39:00Z" data-local-time>Oct 08, 16:39 UTC</time>' in resp.text


async def test_the_local_time_script_is_nonced_and_the_csp_is_unchanged(client, pool, as_principal):
    await insert_review(pool, owner=OWNER, repo=REPO, private=False)
    as_principal(VIEWER)
    resp = _repo_page(client)

    nonce = _csp(resp)["script-src"].split("'nonce-")[1].rstrip("'")
    assert resp.headers["content-security-policy"] == _CSP_BEFORE_CACHE_CONTROL.replace("NONCE", nonce)
    scripts = re.findall(r"<script([^>]*)>(.*?)</script>", resp.text, re.S)
    local = [attrs for attrs, body in scripts if "data-local-time" in body]
    assert local and all(f'nonce="{nonce}"' in attrs for attrs in local)


# --------------------------------------------------------------------------
# 5. The per-delivery footer is for the Reviews list only
# --------------------------------------------------------------------------

_FOOTER = "Reviews are recorded per delivery"


async def test_the_footer_is_on_the_reviews_list(client, pool, as_principal):
    await insert_review(pool, owner=OWNER, repo=REPO, private=False)
    as_principal(VIEWER)
    with patch.object(access, "_is_collaborator", return_value=True):
        assert _FOOTER in client.get(f"/dashboard?repo={OWNER}/{REPO}").text


async def test_the_footer_is_not_on_other_pages(client, pool, as_principal):
    as_principal(VIEWER)
    with patch.object(access, "installed_repositories", return_value=[]), \
         patch.object(access, "_is_collaborator", return_value=True):
        assert _FOOTER not in client.get("/dashboard/repos").text
        assert _FOOTER not in client.get(f"/dashboard/repos/{OWNER}/{REPO}").text
    assert _FOOTER not in _not_found(client, f"/dashboard/reviews/{uuid.uuid4()}")


# --------------------------------------------------------------------------
# 7. The root redirects to the dashboard
# --------------------------------------------------------------------------

async def test_the_root_redirects_to_the_dashboard(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/dashboard"


async def test_the_repo_total_cost_includes_the_viewers_audits(client, pool, as_principal):
    """It counted reviews only, so an audited repo read $0.0000 here while
    the Repositories row (reviews + the viewer's own audits) read $0.0891."""
    await insert_review(pool, owner=OWNER, repo=REPO, private=False, estimated_cost_usd=0.01)
    await _insert_audit(pool, cost=0.0347)
    await _insert_audit(pool, requested_by=OTHER, cost=0.5)
    as_principal(VIEWER)
    stats = _repo_page(client).text.split('class="stats"')[1].split("</div>\n</div>")[0]
    assert "$0.0447" in stats
