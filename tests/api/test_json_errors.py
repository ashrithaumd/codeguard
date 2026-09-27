"""A machine endpoint's 404 must be JSON, and its poller must stop.

Issue #6. `GET /dashboard/audits/{id}.json` returned an HTML error page on
404, because api/main.py's exception handler keys on the path PREFIX:

    if not request.url.path.startswith("/dashboard"):
        return JSONResponse(...)

That rule is right for the page routes and was chosen deliberately over
content negotiation -- /webhook is called by GitHub, which sends no useful
Accept header, and an HTML body in a delivery log would be actively
confusing. But the poll endpoint is a machine endpoint that happens to
live under the same prefix, so it inherited the HTML branch.

THE STATUS CODE WAS ALWAYS RIGHT and nothing leaked. The real consequence
is in the poller, and it is a stuck page rather than a disclosure:

    .then(r => { if (!r.ok) throw new Error(r.status); return r.json(); })
    .catch(() => { delay = min(delay*2, 30000); setTimeout(tick, delay); })

A 404 was treated as a transient blip and backed off, forever. So an audit
row deleted while someone had its page open left that page spinning on
"Running" indefinitely. Reachable today -- rows have been deleted by hand.

Back-off is correct for a 5xx or a dropped connection. It is wrong for a
definitive answer.
"""

from __future__ import annotations

import uuid

import pytest


def test_the_poll_endpoint_404s_with_json(client):
    resp = client.get(f"/dashboard/audits/{uuid.uuid4()}.json")

    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json()["detail"]
    assert "<!doctype html>" not in resp.text.lower()


def test_the_page_route_still_returns_html(client):
    """The prefix rule is still right for the pages. A JSON body here would
    be a worse experience than the HTML error page, and this is the half of
    issue #6 that must NOT change."""
    resp = client.get(f"/dashboard/audits/{uuid.uuid4()}")

    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("text/html")
    assert "<!doctype html>" in resp.text.lower()


def test_the_search_endpoint_is_json_too(client):
    """/dashboard/search is the other machine endpoint under this prefix.
    It does not 404 today, but the rule should cover it rather than naming
    one path -- a rule that lists today's endpoints is one that will be
    wrong when the next is added."""
    from codeguard.api.main import _wants_json

    assert _wants_json("/dashboard/audits/x.json") is True
    assert _wants_json("/dashboard/search") is True
    assert _wants_json("/dashboard/repos") is False
    assert _wants_json("/dashboard") is False


def test_a_webhook_error_is_still_json(client):
    """The reason negotiation was rejected in the first place. GitHub sends
    no useful Accept header, and this must not regress to HTML."""
    resp = client.post("/webhook", content=b"{}", headers={"X-GitHub-Event": "ping"})

    assert resp.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize("path", ["/dashboard/audits/not-a-uuid.json"])
def test_a_malformed_id_is_json_as_well(client, path):
    """FastAPI's own 422 for a bad path parameter goes through the same
    handler. A validation error on a machine endpoint is still machine
    output."""
    resp = client.get(path)

    assert resp.status_code in (404, 422)
    assert resp.headers["content-type"].startswith("application/json")


# --- the poller -----------------------------------------------------------


def test_the_poller_stops_on_a_definitive_404():
    """Asserted against the template's own source, because the alternative
    is a browser.

    Crude, and the crudeness is the point: the behaviour under test is four
    lines of inline JavaScript, and a test that renders the page in a real
    browser would be a large amount of machinery to check that one branch
    exists. What this catches is the branch being deleted.
    """
    from pathlib import Path

    audit_html = Path("codeguard/api/templates/audit.html").read_text(encoding="utf-8")

    assert "404" in audit_html, "the poller does not distinguish a 404 at all"
    # The back-off must not be the only path out of a failed fetch.
    assert "no longer exists" in audit_html or "gone" in audit_html.lower(), (
        "a deleted audit leaves the page spinning with nothing said"
    )
