"""The things a reader has to be able to trust on this page.

Each of these is a defect that was visible on a rendered page, not a
hypothetical: a secret printed in full on a login-free page, a findings
count that disagreed with its own breakdown, a chart caption asserting
something the bars did not show, and headline totals that changed when
you paginated.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from tests.api.conftest import insert_review

SECRET = "sk_live_51HabcdefghijklmnopQ"


def _finding(**over):
    f = {"file": "a.py", "start_line": 1, "end_line": 1, "severity": "HIGH",
         "source_tool": "bandit", "rule_id": "B105", "message": "m",
         "fingerprint": "fp1", "confidence": 1.0}
    f.update(over)
    return f


# --- redaction reaches the rendered page --------------------------------


@pytest.mark.asyncio
async def test_a_secret_in_a_finding_message_is_masked_on_the_page(pool, client):
    """The whole reason redaction exists: a public repo's page is
    readable with no login, and the finding that says "you hardcoded a
    secret" is the one carrying the secret.
    """
    job_id = await insert_review(
        pool, findings_total=1, det=1,
        findings=[_finding(message=f"Possible hardcoded credential: api_secret = '{SECRET}'")],
    )

    text = client.get(f"/dashboard/reviews/{job_id}").text

    assert SECRET not in text
    assert "hardcoded credential" in text, "the finding is still reported, just not its value"


@pytest.mark.asyncio
async def test_a_secret_in_the_summary_body_is_masked(pool, client):
    job_id = await insert_review(pool, summary_body=f"Found api_key = '{SECRET}' in config.py")

    assert SECRET not in client.get(f"/dashboard/reviews/{job_id}").text


@pytest.mark.asyncio
async def test_a_secret_in_a_fix_diff_is_masked(pool, client):
    """A fix for a hardcoded-credential finding is, by construction, a
    diff whose "before" line is the credential.
    """
    job_id = await insert_review(
        pool, findings_total=1, det=1, fix_suggestion_count=1,
        findings=[_finding(message="hardcoded secret")],
        fixes=[{"fingerprint": "fp1",
                "suggestion_body": '```suggestion\nKEY = os.environ["KEY"]\n```',
                "target_file": "a.py", "target_line": 1, "target_end_line": 1,
                "original_text": f'KEY = "{SECRET}"'}],
    )

    text = client.get(f"/dashboard/reviews/{job_id}").text

    assert SECRET not in text
    assert "os.environ" in text, "the replacement half of the diff still renders"


# --- counts agree --------------------------------------------------------


@pytest.mark.asyncio
async def test_the_findings_panel_shows_the_same_total_as_the_composition(pool, client):
    """#214 rendered "Findings 5" beside a composition summing to 20.
    The stored total is authoritative and both places read it.
    """
    job_id = await insert_review(pool, findings_total=4, vc=1, gen=1, det=1, unv=1, findings=[])

    panel = client.get(f"/dashboard/reviews/{job_id}").text.split("<h2>Findings</h2>")[1][:400]

    assert ">4<" in panel


@pytest.mark.asyncio
async def test_a_shorter_detail_list_is_disclosed_not_shown_silently(pool, client):
    job_id = await insert_review(
        pool, findings_total=3, det=3, findings=[_finding(severity="LOW", source_tool="ruff")],
    )

    assert "showing 1" in client.get(f"/dashboard/reviews/{job_id}").text


# --- fix suggestions render as diffs -------------------------------------


@pytest.mark.asyncio
async def test_a_fix_suggestion_renders_as_a_before_and_after_diff(pool, client):
    job_id = await insert_review(
        pool, findings_total=1, det=1, fix_suggestion_count=1,
        findings=[_finding()],
        fixes=[{"fingerprint": "fp1", "suggestion_body": "```suggestion\nnew_line()\n```",
                "target_file": "a.py", "target_line": 1, "target_end_line": 1,
                "original_text": "old_line()"}],
    )

    text = client.get(f"/dashboard/reviews/{job_id}").text

    assert "row del" in text and "old_line()" in text
    assert "row add" in text and "new_line()" in text


@pytest.mark.asyncio
async def test_a_suggestion_with_no_recorded_original_says_so(pool, client):
    """Rather than rendering an empty "before" that reads as "this
    replaces nothing".
    """
    job_id = await insert_review(
        pool, findings_total=1, det=1, fix_suggestion_count=1,
        findings=[_finding()],
        fixes=[{"fingerprint": "fp1", "suggestion_body": "```suggestion\nnew_line()\n```",
                "target_file": "a.py", "target_line": 1}],
    )

    text = client.get(f"/dashboard/reviews/{job_id}").text

    assert "new_line()" in text
    assert "row del" not in text, "no invented before-state"
    assert "only the replacement is shown" in text


@pytest.mark.asyncio
async def test_a_finding_without_a_fix_says_so_rather_than_showing_a_dash(pool, client):
    job_id = await insert_review(pool, findings_total=1, det=1, findings=[_finding()])

    assert "No suggestion" in client.get(f"/dashboard/reviews/{job_id}").text


# --- totals, not "this page" ---------------------------------------------


@pytest.mark.asyncio
async def test_the_kpi_strip_counts_every_visible_review_not_just_the_page(pool, client):
    from codeguard.api.routes import dashboard as d

    for i in range(3):
        await insert_review(pool, pr_number=i, findings_total=2, det=2)

    with patch.object(d, "PAGE_SIZE", 1):
        text = client.get("/dashboard").text

    stats = text.split('class="stats"')[1].split("</div>\n</div>")[0]
    assert ">6<" in stats, "findings is the total across all 3, not the 1 row on this page"
    assert "this page" not in stats


# --- sign in -------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_anonymous_visitor_gets_a_sign_in_button(pool, client):
    await insert_review(pool)

    text = client.get("/dashboard").text

    assert "Sign in with GitHub" in text
    assert "/.auth/login/github" in text
    assert "Signed out" not in text


@pytest.mark.asyncio
async def test_a_signed_in_visitor_gets_sign_out(pool, client):
    await insert_review(pool)

    with patch("codeguard.api.routes.dashboard.client_principal", return_value="alice"):
        text = client.get("/dashboard").text

    assert "alice" in text
    assert "/.auth/logout" in text


# --- the chart lives where its points are comparable ---------------------


@pytest.mark.asyncio
async def test_a_pull_requests_own_reviews_are_listed_on_its_page(pool, client):
    await insert_review(pool, pr_number=7, head_sha="a" * 40)
    await insert_review(pool, pr_number=7, head_sha="b" * 40)
    await insert_review(pool, pr_number=9, head_sha="c" * 40)

    text = client.get("/dashboard/repos/acme/widgets/pulls/7").text

    assert "aaaaaaa" in text and "bbbbbbb" in text
    assert "ccccccc" not in text, "another PR's reviews are not this PR's history"


@pytest.mark.asyncio
async def test_the_repo_page_has_no_cost_chart(pool, client):
    """A repo-wide series mixes pull requests, so adjacent bars can be a
    2-file PR and a 40-file PR and their difference means nothing.
    """
    for sha in ("a", "b", "c"):
        await insert_review(pool, pr_number=7, head_sha=sha * 40)

    assert "Cost per review" not in client.get("/dashboard/repos/acme/widgets").text


@pytest.mark.asyncio
async def test_the_chart_is_hidden_below_three_points(pool, client):
    """Two bars are a comparison, not a trend."""
    for sha in ("a", "b"):
        await insert_review(pool, pr_number=7, head_sha=sha * 40)

    assert "Cost per review" not in client.get("/dashboard/repos/acme/widgets/pulls/7").text


@pytest.mark.asyncio
async def test_the_chart_appears_at_three_points_without_a_causal_caption(pool, client):
    for sha in ("a", "b", "c"):
        await insert_review(pool, pr_number=7, head_sha=sha * 40)
    async with pool.connection() as conn:
        await conn.execute("UPDATE reviews SET estimated_cost_usd = 0.01")

    text = client.get("/dashboard/repos/acme/widgets/pulls/7").text

    assert "Cost per review" in text
    assert "costs a fraction of the first" not in text, "no claim the bars may not support"


@pytest.mark.asyncio
async def test_a_review_links_to_its_neighbour_in_the_same_pull_request(pool, client):
    older = await insert_review(pool, pr_number=7, head_sha="a" * 40)
    newer = await insert_review(pool, pr_number=7, head_sha="b" * 40)

    text = client.get(f"/dashboard/reviews/{newer}").text

    assert f"/dashboard/reviews/{older}" in text
    assert "Older" in text
