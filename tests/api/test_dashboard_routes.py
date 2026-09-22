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
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

from codeguard.api import access
from codeguard.api.main import app

XSS = "<script>alert('pwn')</script>"


@pytest.fixture(autouse=True)
def _clear_access_caches():
    access.reset_caches()
    yield
    access.reset_caches()


@pytest.fixture
async def client(pool):
    app.state.pool = pool
    async with pool.connection() as conn:
        await conn.execute("TRUNCATE reviews")
    with TestClient(app) as c:
        # TestClient's own lifespan would rebuild the pool against the
        # live database; the fixture's test-database pool is reinstated
        # here so every query below hits codeguard_test.
        app.state.pool = pool
        yield c


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
async def test_a_public_review_renders_for_an_anonymous_visitor(pool, client):
    job_id = await _insert(pool, private=False)

    resp = client.get(f"/dashboard/reviews/{job_id}")

    assert resp.status_code == 200
    assert "acme" in resp.text


@pytest.mark.asyncio
async def test_a_private_review_is_404_for_an_anonymous_visitor(pool, client):
    job_id = await _insert(pool, private=True, summary_body="secret plans")

    resp = client.get(f"/dashboard/reviews/{job_id}")

    assert resp.status_code == 404
    assert "secret plans" not in resp.text


@pytest.mark.asyncio
async def test_a_missing_review_is_indistinguishable_from_a_forbidden_one(pool, client):
    """Both answer 404 with the same body. A different status or a
    different message would let an anonymous visitor enumerate which
    (repo, PR) pairs are being reviewed.
    """
    private_id = await _insert(pool, private=True)
    missing = client.get(f"/dashboard/reviews/{uuid.uuid4()}")
    forbidden = client.get(f"/dashboard/reviews/{private_id}")

    assert missing.status_code == forbidden.status_code == 404
    assert missing.text == forbidden.text


@pytest.mark.asyncio
async def test_the_index_omits_private_reviews_entirely(pool, client):
    await _insert(pool, private=False, repo="public-one")
    await _insert(pool, private=True, repo="secret-one")

    resp = client.get("/dashboard")

    assert "public-one" in resp.text
    assert "secret-one" not in resp.text


@pytest.mark.asyncio
async def test_a_repo_page_is_gated_by_its_strictest_review(pool, client):
    """A repo made public does not publish the reviews recorded while it
    was private. The page lists every row it fetched, so one private row
    gates all of them.
    """
    await _insert(pool, repo="flipped", private=True, pr_number=1)
    await _insert(pool, repo="flipped", private=False, pr_number=2)

    assert client.get("/dashboard/repos/acme/flipped").status_code == 404


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
async def test_the_empty_index_explains_itself(pool, client):
    resp = client.get("/dashboard")

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
