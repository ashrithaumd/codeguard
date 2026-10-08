"""Repo page and PR titles.

  * #4 the breadcrumb said "Reviews / <repo>"; the page is reached from
    Repositories, and the trail now says so.
  * #3 the cost chart, restored -- it was removed on Sept 22 because a
    repo-wide series of raw cost puts a 2-file PR beside a 40-file PR and
    the difference says nothing about either. It comes back as cost PER
    REVIEWED FILE, which is comparable across PRs, with each bar labelled
    by its PR.
  * #5 PRs showed only a number. The title has been stored at review time
    since migration 008 (from the webhook payload); only the search palette
    ever showed it.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from codeguard.api import access
from tests.api.conftest import insert_review

OWNER = "ashrithaumd"
REPO = "codeguard-playground"


def _collab():
    return patch.object(access, "_is_collaborator", return_value=True)


async def _two_reviews(pool):
    t0 = datetime.now(timezone.utc) - timedelta(days=2)
    big = await insert_review(pool, owner=OWNER, repo=REPO, private=False, pr_number=5,
                              pr_title="Add retry to the queue", files_reviewed=10, files_seen=10,
                              estimated_cost_usd=0.10, created_at=t0)
    small = await insert_review(pool, owner=OWNER, repo=REPO, private=False, pr_number=6,
                                pr_title="Fix typo", files_reviewed=1, files_seen=1,
                                estimated_cost_usd=0.02, created_at=t0 + timedelta(hours=1))
    return big, small


async def test_the_breadcrumb_starts_at_repositories(client, pool, as_principal):
    await _two_reviews(pool)
    as_principal(OWNER)
    with _collab():
        html = client.get(f"/dashboard/repos/{OWNER}/{REPO}").text

    crumbs = re.search(r'class="crumbs".*?</nav>', html, re.S).group(0)
    assert re.search(r'<a href="/dashboard/repos">Repositories</a>', crumbs)
    assert f"{OWNER}/{REPO}" in crumbs
    assert ">Reviews<" not in crumbs


async def test_the_chart_plots_cost_per_reviewed_file_with_pr_labels(client, pool, as_principal):
    await _two_reviews(pool)
    as_principal(OWNER)
    with _collab():
        html = client.get(f"/dashboard/repos/{OWNER}/{REPO}").text

    assert "Cost per reviewed file" in html
    bars = re.findall(r'<div class="bar-col"[^>]*title="([^"]+)"', html)
    assert len(bars) == 2
    # Oldest first: PR #5 ($0.10 over 10 files), then PR #6 ($0.02 over 1).
    assert bars[0].startswith("#5") and "$0.0100 per file" in bars[0]
    assert bars[1].startswith("#6") and "$0.0200 per file" in bars[1]
    labels = re.findall(r'class="bar-label">([^<]+)<', html)
    assert labels == ["#5", "#6"]
    # The tallest bar is the most expensive PER FILE, not the most expensive.
    heights = [float(h) for h in re.findall(r'class="bar-fill" style="height: ([\d.]+)%"', html)]
    assert heights[1] == 100 and heights[0] == 50


async def test_a_review_that_reviewed_no_files_is_not_a_division_by_zero(client, pool, as_principal):
    await insert_review(pool, owner=OWNER, repo=REPO, private=False, pr_number=7,
                        files_reviewed=0, files_seen=3, estimated_cost_usd=0.0)
    as_principal(OWNER)
    with _collab():
        resp = client.get(f"/dashboard/repos/{OWNER}/{REPO}")
    assert resp.status_code == 200


async def test_pr_titles_appear_beside_their_numbers(client, pool, as_principal):
    big, _ = await _two_reviews(pool)
    as_principal(OWNER)
    with _collab():
        repo_page = client.get(f"/dashboard/repos/{OWNER}/{REPO}").text
        # Filtered, so the signed-in landing redirect to Repositories does
        # not apply and this is the Reviews list itself.
        index = client.get(f"/dashboard?repo={OWNER}/{REPO}").text
        review = client.get(f"/dashboard/reviews/{big}").text
        pr = client.get(f"/dashboard/repos/{OWNER}/{REPO}/pulls/5").text

    for page in (repo_page, index, review, pr):
        assert "Add retry to the queue" in page


async def test_a_pr_title_is_escaped(client, pool, as_principal):
    await insert_review(pool, owner=OWNER, repo=REPO, private=False, pr_number=8,
                        pr_title="<script>alert(1)</script>")
    as_principal(OWNER)
    with _collab():
        html = client.get(f"/dashboard/repos/{OWNER}/{REPO}").text
    assert "<script>alert(1)" not in html
    assert "&lt;script&gt;alert(1)" in html


async def test_the_reviews_page_links_to_repositories_instead_of_repeating_it(client, pool, as_principal):
    """#10: the Reviews page ended with a Repositories table that
    duplicated the Repositories page. One link instead."""
    await _two_reviews(pool)
    as_principal(OWNER)
    with _collab():
        html = client.get(f"/dashboard?repo={OWNER}/{REPO}").text

    assert not re.search(r"<h2>Repositories</h2>", html)
    assert re.search(r'<a[^>]+href="/dashboard/repos"[^>]*>[^<]*per-repository', html, re.I)
