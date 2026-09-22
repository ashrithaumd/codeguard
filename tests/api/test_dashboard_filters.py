"""URL filters and the quick-jump search index.

The filters live in the query string so a filtered view is a URL. That
makes two things testable that a JS-side filter would not be: the link
is the state, and visibility is enforced in SQL alongside the filter
rather than after it.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from codeguard.api.dashboard_queries import Filters
from tests.api.conftest import insert_review


def _finding(severity="HIGH", path="a.py"):
    return {"file": path, "start_line": 1, "end_line": 1, "severity": severity,
            "source_tool": "bandit", "rule_id": "B105", "message": "m",
            "fingerprint": "fp", "confidence": 1.0}


# --- parsing -------------------------------------------------------------


def test_an_unknown_filter_value_is_dropped_not_rejected():
    """A stale bookmark should degrade to the unfiltered page, not to an
    error page.
    """
    f = Filters(severity="BANANA", gate="sideways", date_from="not-a-date")

    assert f.severity == "" and f.gate == "" and f.date_from is None
    assert not f.active


def test_severity_is_accepted_case_insensitively():
    assert Filters(severity="critical").severity == "CRITICAL"


def test_the_query_string_round_trips_and_can_drop_one_filter():
    f = Filters(repo="acme/widgets", severity="HIGH", gate="blocked")

    assert "repo=acme%2Fwidgets" in f.query_string()
    assert "severity=HIGH" not in f.query_string(severity="")
    assert "gate=blocked" in f.query_string(severity="")


# --- filtering -----------------------------------------------------------


@pytest.mark.asyncio
async def test_filtering_by_repo(pool, client):
    await insert_review(pool, repo="widgets")
    await insert_review(pool, repo="gadgets")

    text = client.get("/dashboard?repo=acme/gadgets").text

    assert "gadgets" in text
    assert ">widgets<" not in text


@pytest.mark.asyncio
async def test_filtering_by_gate_result(pool, client):
    await insert_review(pool, pr_number=1, check_conclusion="failure")
    await insert_review(pool, pr_number=2, check_conclusion="success")

    blocked = client.get("/dashboard?gate=blocked").text

    assert "Blocked" in blocked
    assert ">1<" in blocked.split('class="stats"')[1][:400], "one review matched"


@pytest.mark.asyncio
async def test_filtering_by_severity_reads_the_finding_detail(pool, client):
    """Reviews store per-trust-bucket counts but no severity counts, so
    this has to look inside findings_json — the only place severity is
    recorded.
    """
    await insert_review(pool, pr_number=1, findings_total=1, det=1,
                        findings=[_finding(severity="CRITICAL")])
    await insert_review(pool, pr_number=2, findings_total=1, det=1,
                        findings=[_finding(severity="LOW")])

    text = client.get("/dashboard?severity=CRITICAL").text

    assert ">1<" in text.split('class="stats"')[1][:400]


@pytest.mark.asyncio
async def test_filtering_by_date_range_includes_the_whole_end_day(pool, client):
    """Picking the same date at both ends means "that day", not "the
    instant midnight began".
    """
    job_id = await insert_review(pool)
    async with pool.connection() as conn:
        await conn.execute("UPDATE reviews SET created_at = '2026-09-10 14:00:00+00'")

    same_day = client.get("/dashboard?from=2026-09-10&to=2026-09-10").text
    assert str(job_id) in same_day

    before = client.get("/dashboard?from=2026-09-11").text
    assert str(job_id) not in before


@pytest.mark.asyncio
async def test_the_totals_describe_the_filtered_set(pool, client):
    """The listing and the headline numbers must never describe
    different subsets.
    """
    await insert_review(pool, pr_number=1, check_conclusion="failure", findings_total=5, det=5)
    await insert_review(pool, pr_number=2, check_conclusion="success", findings_total=9, det=9)

    stats = client.get("/dashboard?gate=blocked").text.split('class="stats"')[1][:500]

    assert ">5<" in stats
    assert ">9<" not in stats


@pytest.mark.asyncio
async def test_a_filter_cannot_widen_visibility(pool, client):
    """Filters narrow; they never reach past the visibility clause."""
    await insert_review(pool, repo="secret-one", private=True, check_conclusion="failure")

    text = client.get("/dashboard?gate=blocked").text

    assert "secret-one" not in text


@pytest.mark.asyncio
async def test_active_filters_are_shown_with_a_way_to_clear_each(pool, client):
    await insert_review(pool, check_conclusion="failure")

    text = client.get("/dashboard?gate=blocked&severity=HIGH").text

    assert "Gate: Blocked" in text
    assert "Severity: High" in text
    # Each chip drops only its own filter.
    assert "gate=blocked" in text and "severity=HIGH" in text


# --- quick-jump search index ---------------------------------------------


@pytest.mark.asyncio
async def test_the_search_index_offers_repos_pulls_and_files(pool, client):
    await insert_review(
        pool, repo="widgets", pr_number=214, pr_title="Add idempotency keys",
        findings_total=1, det=1, findings=[_finding(path="billing/charge.py")],
    )

    data = client.get("/dashboard/search").json()

    assert {"owner": "acme", "repo": "widgets",
            "url": "/dashboard/repos/acme/widgets"} in data["repos"]
    assert data["pulls"][0]["number"] == 214
    assert data["pulls"][0]["title"] == "Add idempotency keys"
    assert any(f["path"] == "billing/charge.py" for f in data["files"])


@pytest.mark.asyncio
async def test_the_search_index_never_leaks_a_private_repo_to_anonymous(pool, client):
    """The palette is the easiest place to leak a name, because it lists
    things rather than being asked about one.
    """
    await insert_review(pool, repo="secret-one", private=True, pr_title="Rotate the prod key")

    data = client.get("/dashboard/search").json()

    assert data["repos"] == []
    assert data["pulls"] == []


@pytest.mark.asyncio
async def test_the_search_index_shows_a_private_repo_to_someone_who_can_see_it(pool, client):
    from codeguard.api import access

    await insert_review(pool, repo="secret-one", private=True, pr_title="Rotate the prod key")

    with patch.object(access, "_is_collaborator", return_value=True), \
         patch("codeguard.api.routes.dashboard.client_principal", return_value="alice"):
        data = client.get("/dashboard/search").json()

    assert data["repos"][0]["repo"] == "secret-one"
    assert data["pulls"][0]["title"] == "Rotate the prod key"


@pytest.mark.asyncio
async def test_the_palette_is_reachable_from_every_page(pool, client):
    job_id = await insert_review(pool)

    for url in ["/dashboard", "/dashboard/repos/acme/widgets",
                "/dashboard/repos/acme/widgets/pulls/7", f"/dashboard/reviews/{job_id}"]:
        assert 'id="palette"' in client.get(url).text, url
