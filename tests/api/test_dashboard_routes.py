"""The dashboard's routes, end to end against a real database.

Two things are being pinned that nothing else can pin:

  - a review the visitor may not see answers 404, with a body that does
    not reveal whether it exists. 403 would confirm existence, which is
    precisely what a private repo hides.
  - stored text is ESCAPED. migrations/006 carries an explicit security
    block about this, because Finding.message is tool-generated but
    echoes fragments of the scanned code, i.e. text a PR author writes.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

import pytest
from psycopg.types.json import Jsonb

from codeguard.api import access

XSS = "<script>alert('pwn')</script>"


@pytest.fixture(autouse=True)
def _clear_access_caches():
    access.reset_caches()
    yield
    access.reset_caches()


async def _insert(pool, **over):
    row = dict(
        job_id=uuid.uuid4(), owner="acme", repo="widgets", pr_number=7,
        head_sha="a" * 40, action="opened", private=False,
        summary_body="all good", check_conclusion="success",
        gate_threshold="CRITICAL", fix_threshold="HIGH",
        files_seen=1, files_reviewed=1, findings_total=0,
        vc=0, gen=0, det=0, unv=0,
        dismissed_count=0, inline_count=0, fix_suggestion_count=0,
        budget_exceeded=False, findings=[],
    )
    row.update(over)
    async with pool.connection() as conn:
        await conn.execute(
            """
            INSERT INTO reviews (
                job_id, owner, repo, pr_number, head_sha, action, private,
                summary_body, check_conclusion, gate_threshold, fix_threshold,
                files_seen, files_reviewed, findings_total,
                findings_verdict_confirmed, findings_generative,
                findings_deterministic, findings_unverified,
                dismissed_count, inline_count, fix_suggestion_count,
                budget_exceeded, findings_json
            ) VALUES (%s,%s,%s,%s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s, %s,%s,%s,%s,
                      %s,%s,%s, %s,%s)
            """,
            (row["job_id"], row["owner"], row["repo"], row["pr_number"], row["head_sha"],
             row["action"], row["private"], row["summary_body"], row["check_conclusion"],
             row["gate_threshold"], row["fix_threshold"], row["files_seen"],
             row["files_reviewed"], row["findings_total"], row["vc"], row["gen"],
             row["det"], row["unv"], row["dismissed_count"], row["inline_count"],
             row["fix_suggestion_count"], row["budget_exceeded"], Jsonb(row["findings"])),
        )
    return row["job_id"]


# --- visibility ---------------------------------------------------------


@pytest.mark.asyncio
async def test_a_public_review_is_404_for_an_anonymous_visitor(pool, anon_client):
    """Was test_a_public_review_renders_for_an_anonymous_visitor, and
    asserted 200. The premise changed, not the test.

    A review of public code is public information; the PAGE is not --
    which repos this installation reviews, the PR titles and the spend are
    published by no repository. So the dashboard now requires an access
    decision on every row, public included, and an anonymous visitor sees
    nothing rather than everything.
    """
    job_id = await _insert(pool, private=False)

    resp = anon_client.get(f"/dashboard/reviews/{job_id}")

    assert resp.status_code == 404
    assert "acme" not in resp.text


@pytest.mark.asyncio
async def test_a_public_review_renders_for_a_signed_in_collaborator(pool, client):
    """The other side of it: gating on access must not hide a repo from
    someone who has access."""
    job_id = await _insert(pool, private=False)

    resp = client.get(f"/dashboard/reviews/{job_id}")

    assert resp.status_code == 200
    assert "acme" in resp.text


@pytest.mark.asyncio
async def test_a_private_review_is_404_for_an_anonymous_visitor(pool, anon_client):
    job_id = await _insert(pool, private=True, summary_body="secret plans")

    resp = anon_client.get(f"/dashboard/reviews/{job_id}")

    assert resp.status_code == 404
    assert "secret plans" not in resp.text


@pytest.mark.asyncio
async def test_a_missing_review_is_indistinguishable_from_a_forbidden_one(pool, anon_client):
    """Both answer 404 with the same body. A different status or a
    different message would let an anonymous visitor enumerate which
    (repo, PR) pairs are being reviewed.
    """
    private_id = await _insert(pool, private=True)
    missing_id = uuid.uuid4()
    missing = anon_client.get(f"/dashboard/reviews/{missing_id}")
    forbidden = anon_client.get(f"/dashboard/reviews/{private_id}")

    assert missing.status_code == forbidden.status_code == 404

    # Compared with each response's own id removed. The sign-in button
    # carries the requested path in post_login_redirect_uri, so the two
    # bodies differ by the URL the caller themselves supplied — which
    # tells them nothing. The property under test is that nothing ELSE
    # differs, i.e. the response never reveals whether the review exists.
    assert missing.text.replace(str(missing_id), "ID") == forbidden.text.replace(str(private_id), "ID")


@pytest.mark.asyncio
async def test_the_index_omits_private_reviews_entirely(pool, client):
    """Per-repo access, not a blanket answer.

    The visitor is a collaborator on public-one and not on secret-one,
    which is the only shape that can distinguish "the filter works" from
    "the page is empty". A blanket True would show both; a blanket False
    would show neither, and either would pass an assertion about one of
    them for the wrong reason.
    """
    await _insert(pool, private=False, repo="public-one")
    await _insert(pool, private=True, repo="secret-one")

    with patch.object(access, "_is_collaborator",
                      side_effect=lambda o, r, u: r == "public-one"):
        resp = client.get("/dashboard?page=1")

    assert "public-one" in resp.text
    assert "secret-one" not in resp.text


@pytest.mark.asyncio
async def test_a_repo_page_needs_access_whatever_its_rows_say(pool, anon_client):
    """Was test_a_repo_page_is_gated_by_its_strictest_review.

    That rule -- "any private row gates the whole page" -- is gone because
    it is subsumed. The question is no longer "is any row private" but
    "may this person see this repository", which is strictly stronger and
    does not depend on what the rows happen to say. A repo whose rows are
    ALL public is now gated too.
    """
    await _insert(pool, repo="flipped", private=True, pr_number=1)
    await _insert(pool, repo="flipped", private=False, pr_number=2)
    assert anon_client.get("/dashboard/repos/acme/flipped").status_code == 404

    await _insert(pool, repo="allpublic", private=False, pr_number=3)
    assert anon_client.get("/dashboard/repos/acme/allpublic").status_code == 404


@pytest.mark.asyncio
async def test_a_signed_in_collaborator_sees_the_private_review(pool, client):
    job_id = await _insert(pool, private=True, summary_body="internal only")

    with patch.object(access, "_is_collaborator", return_value=True), \
         patch("codeguard.api.routes.dashboard.client_principal", return_value="alice"):
        resp = client.get(f"/dashboard/reviews/{job_id}")

    assert resp.status_code == 200
    assert "internal only" in resp.text


# --- escaping -----------------------------------------------------------


@pytest.mark.asyncio
async def test_a_finding_message_is_escaped_not_executed(pool, client):
    """Finding.message is attacker-influenceable: Bandit's own
    hardcoded-secret message includes the matched source line verbatim.
    """
    job_id = await _insert(
        pool, findings_total=1, det=1,
        findings=[{"file": "a.py", "start_line": 1, "end_line": 1, "severity": "LOW",
                   "source_tool": "ruff", "rule_id": "E501", "message": XSS,
                   "fingerprint": "abc123", "confidence": 1.0}],
    )

    resp = client.get(f"/dashboard/reviews/{job_id}")

    assert resp.status_code == 200
    assert XSS not in resp.text, "the raw script tag must never reach the page"
    assert "&lt;script&gt;" in resp.text, "it should still be VISIBLE, just inert"


@pytest.mark.asyncio
async def test_a_hostile_file_path_is_escaped(pool, client):
    job_id = await _insert(
        pool, findings_total=1, det=1,
        findings=[{"file": XSS, "start_line": 1, "end_line": 1, "severity": "LOW",
                   "source_tool": "ruff", "rule_id": "E501", "message": "m",
                   "fingerprint": "abc123", "confidence": 1.0}],
    )

    resp = client.get(f"/dashboard/reviews/{job_id}")

    assert XSS not in resp.text


@pytest.mark.asyncio
async def test_the_summary_body_is_shown_as_text_not_rendered_as_html(pool, client):
    """summary_body is Markdown that GitHub rendered inside its own
    sandbox with its own sanitiser. We do not inherit that.
    """
    job_id = await _insert(pool, summary_body=f"Review complete. {XSS}")

    resp = client.get(f"/dashboard/reviews/{job_id}")

    assert XSS not in resp.text
    assert "&lt;script&gt;" in resp.text


@pytest.mark.asyncio
async def test_a_hostile_repo_name_is_escaped_on_the_index(pool, client):
    await _insert(pool, repo=XSS, private=False)

    resp = client.get("/dashboard")

    assert XSS not in resp.text


# --- states -------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_empty_index_explains_itself(pool, anon_client):
    """Anonymous, and asking for the log explicitly.

    Anonymous visitors now see no reviews at all rather than the public
    ones, so this is the copy they land on.
    """
    resp = anon_client.get("/dashboard?page=1")

    assert resp.status_code == 200
    assert "Nothing public to show" in resp.text


@pytest.mark.asyncio
async def test_a_review_with_no_findings_says_so_rather_than_showing_nothing(pool, client):
    job_id = await _insert(pool, findings_total=0, findings=[])

    resp = client.get(f"/dashboard/reviews/{job_id}")

    assert "No findings" in resp.text


@pytest.mark.asyncio
async def test_a_dashboard_404_renders_html_not_json(pool, client):
    resp = client.get(f"/dashboard/reviews/{uuid.uuid4()}")

    assert resp.status_code == 404
    assert "text/html" in resp.headers["content-type"]
    assert "Not found" in resp.text


@pytest.mark.asyncio
async def test_a_non_dashboard_404_still_renders_json(pool, client):
    """GitHub calls /webhook and sends no useful Accept header; an HTML
    body in a delivery log would be actively confusing.
    """
    resp = client.get("/no-such-route")

    assert resp.status_code == 404
    assert "application/json" in resp.headers["content-type"]


# --- explaining itself --------------------------------------------------


@pytest.mark.asyncio
async def test_the_index_says_what_codeguard_is(pool, client):
    """The rule this page is held to: nothing on it should require
    having read the README.
    """
    await _insert(pool)

    # ?page=1 because a bare /dashboard redirects a signed-in visitor to
    # the repositories page, which has its own copy.
    text = client.get("/dashboard?page=1").text

    assert "reviews every pull request" in text


@pytest.mark.asyncio
async def test_a_signed_in_user_with_no_reviews_gets_setup_instructions(pool, client):
    """Not an error and not a blank table — "not set up yet". The state
    has to say what CodeGuard is and how to get a first review.

    Asks for the log explicitly. A bare /dashboard now redirects a
    signed-in visitor to the repositories page, which is the landing
    view and has its own setup state (covered in test_repositories.py);
    this is still the right copy for the review log itself, which is
    where anyone arriving from a shared or filtered link lands.
    """
    with patch("codeguard.api.routes.dashboard.client_principal", return_value="alice"):
        text = client.get("/dashboard?page=1").text

    assert "No reviews yet" in text
    assert "GitHub App" in text
    assert "Install the CodeGuard GitHub App" in text


@pytest.mark.asyncio
async def test_an_anonymous_visitor_with_no_reviews_is_told_to_sign_in_instead(pool, anon_client):
    """Install instructions would be the wrong advice for someone who
    simply is not signed in — the reviews may well exist.
    """
    text = anon_client.get("/dashboard").text

    assert "Nothing public to show" in text
    assert "Install the CodeGuard GitHub App" not in text


@pytest.mark.asyncio
async def test_every_column_term_carries_a_definition(pool, client):
    """Each internal word in a column header is explained in place.
    Asserts the definition text, not just the attribute, so a term
    wired to an empty string still fails.
    """
    await _insert(pool)

    text = client.get("/dashboard?page=1").text

    for phrase in [
        "Whether this review blocked the pull request",   # Gate
        "How much of this review was machine-verified",   # Mix
        "an LLM then confirmed it",                       # Verdict-confirmed
        "no scanner found it",                            # Generative
        "does not need interpreting",                     # Deterministic
        "did not happen",                                 # Unverified
        "posted as comments on specific lines",           # Inline
        "one-click suggested fix",                        # Fixes
    ]:
        assert phrase in text, f"missing definition: {phrase}"


@pytest.mark.asyncio
async def test_the_mix_legend_sits_in_its_own_column_header(pool, client):
    """The legend describes the MIX bar, so it lives in that column's
    header rather than floating in the panel header.
    """
    await _insert(pool)

    text = client.get("/dashboard?page=1").text
    head = text.split("<tbody>")[0]

    assert "mix-legend" in head, "the legend belongs inside the table header"
    panel_head = text.split('<div class="panel-head">')[1].split("</div>")[0]
    assert "mix-legend" not in panel_head


@pytest.mark.asyncio
async def test_rows_are_navigable_and_look_it(pool, client):
    job_id = await _insert(pool)

    text = client.get("/dashboard?page=1").text

    assert f'data-href="/dashboard/reviews/{job_id}"' in text
    assert 'class="row-link"' in text
    assert 'class="chev"' in text, "a chevron marks the row as openable"


@pytest.mark.asyncio
async def test_the_review_page_says_what_a_review_is(pool, client):
    job_id = await _insert(pool)

    text = client.get(f"/dashboard/reviews/{job_id}").text

    assert "single pass over one push" in text
