"""Every dashboard response must carry its security headers.

WHAT THESE DEFEND, specifically, rather than as a checklist:

  * frame-ancestors 'none' / X-Frame-Options: the dashboard is behind a
    cookie session, so a page that can frame it can clickjack the "Run
    audit" button -- spend, on a click the operator meant for something
    else. This is the CSRF attack from csrf.py wearing a different hat,
    and the token does not stop it, because a framed click is a real
    same-site submit from our own page.
  * script-src with a nonce and NO 'unsafe-inline': the dashboard renders
    repository names, PR titles, scanner messages and Markdown summaries
    that a pull-request author controls. Autoescaping is what stops those
    becoming script; the CSP is what stops a single missed escape from
    mattering.
  * default-src 'none': so a new sink -- an iframe, a websocket, a
    beacon -- is denied by default rather than allowed until someone
    notices.
  * nosniff: a stored report served as text must not be re-interpreted as
    HTML by a browser guessing at content type.
  * Referrer-Policy same-origin: dashboard URLs contain owner, repo and
    PR number. Following an external link from a report should not hand
    those to the destination -- and same-origin hands it nothing at all.
    It was no-referrer, which broke the audit button: EasyAuth's own
    anti-forgery check on authenticated POSTs is Referer-based. See
    test_the_referrer_policy_leaves_a_same_origin_referer_intact.
  * HSTS: only on requests that arrived over HTTPS. Sending it over local
    http would be ignored by browsers, but gating it keeps the header
    honest about what it is asserting.

THE FAILURE MODE THESE TESTS EXIST FOR is not a missing header -- it is a
CSP that is present and breaks the page. The dashboard has three inline
<script> blocks, so a nonce that does not reach them turns every
interactive control off while every header assertion still passes. Two
tests below check the nonce actually lands, and one checks the templates
structurally.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from codeguard.api import access
from codeguard.config import Settings, get_settings

OWNER = "ashrithaumd"
PUBLIC = "codeguard-playground"

# Machine endpoints. A CSP on a JSON health probe protects nothing, and a
# probe that starts receiving HSTS is a surprise nobody asked for.
EXCLUDED = ["/health", "/ready", "/metrics"]


@pytest.fixture
def as_principal(monkeypatch):
    def _sign_in(login: str | None):
        base = get_settings().model_dump()
        base.update({
            "dashboard_dev_principal": login or "",
            "dashboard_trust_dev_principal": bool(login),
        })
        patched = Settings(**base)
        monkeypatch.setattr("codeguard.api.auth.get_settings", lambda: patched)
        monkeypatch.setattr("codeguard.api.routes.dashboard.get_settings", lambda: patched)
        return patched
    return _sign_in


def _csp(resp) -> dict[str, str]:
    """The CSP parsed into directive -> value, so assertions name a
    directive rather than matching a substring of the whole policy."""
    raw = resp.headers["content-security-policy"]
    out = {}
    for part in raw.split(";"):
        part = part.strip()
        if part:
            name, _, value = part.partition(" ")
            out[name] = value.strip()
    return out


def _dashboard(client):
    with patch.object(access, "installed_repositories", return_value=[]), \
         patch.object(access, "_is_collaborator", return_value=True):
        return client.get("/dashboard/repos")


# --------------------------------------------------------------------------
# The headers themselves
# --------------------------------------------------------------------------


def test_the_dashboard_denies_being_framed(client):
    """Clickjacking the audit button. frame-ancestors is the modern
    control; X-Frame-Options is there for what does not honour it."""
    resp = _dashboard(client)
    assert _csp(resp)["frame-ancestors"] == "'none'"
    assert resp.headers["x-frame-options"].upper() == "DENY"


def test_the_policy_denies_everything_by_default(client):
    resp = _dashboard(client)
    csp = _csp(resp)
    assert csp["default-src"] == "'none'"
    assert csp["object-src"] == "'none'"
    assert csp["base-uri"] == "'none'"
    assert csp["form-action"] == "'self'"


def test_script_src_has_a_nonce_and_no_unsafe_inline(client):
    """'unsafe-inline' would make the nonce decorative: a browser that
    sees both ignores the nonce and allows any inline script, which is
    precisely the injection this is meant to survive."""
    csp = _csp(_dashboard(client))
    assert "'nonce-" in csp["script-src"]
    assert "unsafe-inline" not in csp["script-src"]
    assert "unsafe-eval" not in csp["script-src"]


def test_nosniff_and_referrer_policy_are_set(client):
    resp = _dashboard(client)
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "same-origin"


def test_hsts_is_sent_only_over_https(client):
    """The header asserts "always reach me over TLS". Sent on a plaintext
    local request it is both ignored and untrue, so it is gated on the
    proto the ingress reports rather than sent unconditionally."""
    with patch.object(access, "installed_repositories", return_value=[]), \
         patch.object(access, "_is_collaborator", return_value=True):
        plain = client.get("/dashboard/repos")
        secure = client.get("/dashboard/repos", headers={"x-forwarded-proto": "https"})

    assert "strict-transport-security" not in plain.headers
    assert "max-age=" in secure.headers["strict-transport-security"]
    assert "includeSubDomains" in secure.headers["strict-transport-security"]


def test_the_fonts_the_page_actually_uses_are_allowed(client):
    """A policy that forbids what base.html loads is an outage, not a
    control. The page pulls its stylesheet from Google Fonts and its font
    files from gstatic."""
    csp = _csp(_dashboard(client))
    assert "fonts.googleapis.com" in csp["style-src"]
    assert "fonts.gstatic.com" in csp["font-src"]
    assert "'self'" in csp["style-src"]


def test_the_audit_poll_is_allowed_to_reach_us(client):
    """The audit page polls its own status with fetch. Under
    default-src 'none' that needs connect-src."""
    csp = _csp(_dashboard(client))
    assert csp["connect-src"] == "'self'"


# --------------------------------------------------------------------------
# The nonce has to actually reach the page
# --------------------------------------------------------------------------


def test_every_inline_script_carries_the_nonce(client):
    """The test this file exists for.

    A CSP can be perfect and still break the dashboard: three templates
    have inline <script> blocks, and any one of them without the nonce is
    silently dead. Counts the tags rather than checking that the nonce
    appears somewhere in the body.
    """
    import re

    resp = _dashboard(client)
    nonce = _csp(resp)["script-src"].split("'nonce-")[1].split("'")[0]

    opens = re.findall(r"<script\b[^>]*>", resp.text)
    assert opens, "no inline script found -- has base.html changed?"
    unnonced = [tag for tag in opens if f'nonce="{nonce}"' not in tag]
    assert unnonced == [], f"these script tags would be blocked by the CSP: {unnonced}"


def test_the_nonce_is_different_on_every_request(client):
    """A reused nonce is a permanently valid one: an injected script only
    has to carry the value from any earlier page view."""
    first = _csp(_dashboard(client))["script-src"]
    second = _csp(_dashboard(client))["script-src"]
    assert first != second


def test_no_template_has_an_inline_script_without_a_nonce():
    """Structural, for the template nobody has rendered in a test yet.

    The per-response test above only sees the pages these tests load. A
    new inline block in a template with no test coverage would ship
    broken, and the symptom -- one control quietly not working -- is easy
    to miss.
    """
    import re
    from pathlib import Path

    templates = Path("codeguard/api/templates")
    offenders = []
    for path in sorted(templates.glob("*.html")):
        for tag in re.findall(r"<script\b[^>]*>", path.read_text(encoding="utf-8")):
            # A src= tag is covered by script-src 'self' and needs no nonce.
            if "src=" not in tag and "nonce=" not in tag:
                offenders.append(f"{path.name}: {tag}")

    assert offenders == [], f"inline scripts with no nonce: {offenders}"


# --------------------------------------------------------------------------
# What must NOT get them
# --------------------------------------------------------------------------


@pytest.mark.parametrize("path", EXCLUDED)
def test_the_machine_endpoints_are_left_alone(client, path):
    resp = client.get(path)
    assert "content-security-policy" not in resp.headers, path
    assert "strict-transport-security" not in resp.headers, path


def test_the_webhook_is_left_alone(client):
    """GitHub is the client here, not a browser. It also must not have its
    response shape changed by anything in this middleware."""
    resp = client.post("/webhook", json={}, headers={"X-GitHub-Event": "ping"})
    assert "content-security-policy" not in resp.headers


def test_static_assets_still_get_nosniff(client):
    """Not excluded: a stylesheet served with a guessable type is exactly
    what nosniff is for. Only the machine endpoints opt out."""
    resp = client.get("/static/dashboard.css")
    assert resp.status_code == 200
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_an_error_page_is_not_an_escape_hatch(client, as_principal):
    """A 404 is rendered HTML too, and it is the response an attacker can
    reach without an account. Headers must not depend on the happy path."""
    as_principal(None)
    resp = client.get("/dashboard/repos/nobody/nothing/999")
    assert resp.status_code == 404
    assert _csp(resp)["frame-ancestors"] == "'none'"
    assert resp.headers["x-content-type-options"] == "nosniff"


def test_the_policy_allows_no_external_source_the_templates_do_not_use():
    """The policy and the templates must not drift apart.

    Every host in the CSP is there because something loads from it. An
    allowance left behind after the thing that needed it was removed is a
    hole nobody can account for later -- this caught a leftover `data:` in
    img-src for a favicon that does not exist.
    """
    import re
    from pathlib import Path

    from codeguard.api.headers import policy

    allowed = {
        part for part in re.findall(r"https://[^\s;]+", policy("n"))
    }
    used = set()
    for path in sorted(Path("codeguard/api/templates").glob("*.html")):
        for url in re.findall(r"https://[^\"'\s>]+", path.read_text(encoding="utf-8")):
            used.add("https://" + url.split("//", 1)[1].split("/")[0])

    assert used, "no external resource found -- has base.html changed?"
    assert used <= allowed, f"templates load from hosts the CSP forbids: {used - allowed}"
    assert allowed <= used, f"the CSP allows hosts nothing loads from: {allowed - used}"


# --------------------------------------------------------------------------
# Coverage: every HTML page, not just the ones a header test happened to
# load. The nonce is per RENDER PATH, and a page that does not go through
# dashboard._page gets an empty one -- which is invisible, because the
# page still renders and only its scripts stop working.
# --------------------------------------------------------------------------


def _inline_script_templates() -> set[str]:
    """Page templates whose OUTPUT contains an inline <script>.

    Follows {% extends %}, because base.html holds two of the three inline
    blocks: matching on a template's own text would say error.html has no
    script when every error page it renders has two.
    """
    import re
    from pathlib import Path

    directory = Path("codeguard/api/templates")
    own: dict[str, bool] = {}
    parent: dict[str, str] = {}
    for path in sorted(directory.glob("*.html")):
        text = path.read_text(encoding="utf-8")
        own[path.name] = any(
            "src=" not in tag for tag in re.findall(r"<script\b[^>]*>", text)
        )
        found = re.search(r'{%\s*extends\s*"([^"]+)"', text)
        if found:
            parent[path.name] = found.group(1)

    def inherits_a_script(name: str) -> bool:
        seen = set()
        while name and name not in seen:
            if own.get(name):
                return True
            seen.add(name)
            name = parent.get(name, "")
        return False

    # Pages only. _macros.html is included rather than rendered, and a
    # template something else extends is a layout -- base.html is never a
    # response on its own, so requiring a request that renders it would be
    # asking for a URL that does not exist.
    layouts = set(parent.values())
    return {
        n for n in own
        if not n.startswith("_") and n not in layouts and inherits_a_script(n)
    }


async def _render_every_page(client, pool) -> dict[str, object]:
    """One response per page template, keyed by template name.

    Real requests rather than direct template calls: the thing under test
    is which RENDER PATH a page takes, and calling the template directly
    would supply a context the route does not.
    """
    from codeguard.api import audits as audits_mod
    from tests.api.conftest import insert_review

    job_id = await insert_review(pool, owner=OWNER, repo=PUBLIC, private=False, pr_number=7)
    audit = await audits_mod.request_audit(
        pool, owner=OWNER, repo=PUBLIC, requested_by="test-user", private=False,
    )
    await audits_mod.finish_audit(pool, audit["id"], status="done", report_markdown="# report")

    with patch.object(access, "installed_repositories", return_value=[]), \
         patch.object(access, "_is_collaborator", return_value=True):
        return {
            # /dashboard redirects to /dashboard/repos when signed in, so
            # index.html needs a filtered URL to be the page that renders.
            "index.html": client.get(f"/dashboard?repo={PUBLIC}"),
            "repositories.html": client.get("/dashboard/repos"),
            "repo.html": client.get(f"/dashboard/repos/{OWNER}/{PUBLIC}"),
            "pr.html": client.get(f"/dashboard/repos/{OWNER}/{PUBLIC}/pulls/7"),
            "review.html": client.get(f"/dashboard/reviews/{job_id}"),
            "audit.html": client.get(f"/dashboard/audits/{audit['id']}"),
            # The handler in api/main.py, not a route. This is the page the
            # coverage gap was hiding in.
            "error.html": client.get("/dashboard/reviews/" + "0" * 8 + "-0000-0000-0000-" + "0" * 12),
        }


async def test_every_page_with_an_inline_script_is_covered_here(client, pool):
    """The guard on the guard.

    Asserts the mapping below is complete, so a new page template cannot
    be added without either carrying a nonce test or failing this.
    """
    rendered = await _render_every_page(client, pool)
    expected = _inline_script_templates()
    assert expected, "no page template has an inline script -- has base.html changed?"
    assert expected <= set(rendered), (
        f"these page templates render an inline script but are not checked "
        f"for a nonce: {sorted(expected - set(rendered))}"
    )


async def test_every_page_carries_a_working_nonce(client, pool):
    """The regression this was written for.

    The error handler in api/main.py builds its own TemplateResponse
    instead of going through dashboard._page, so it supplied no csp_nonce
    -- and base.html rendered `nonce=""` while the header carried a real
    value. Every script on every 404, 409 and 400 page was blocked, and
    nothing failed: the page looked right, the theme toggle just did
    nothing and a dark-mode reader got a flash of white on every error.
    """
    import re

    rendered = await _render_every_page(client, pool)

    # FIRST, or this test is vacuous: a page that 404s renders error.html,
    # which has a correct nonce, so every assertion below would pass while
    # six of the seven templates went unrendered. 404 is expected for
    # error.html alone.
    statuses = {name: resp.status_code for name, resp in rendered.items()}
    assert statuses == {
        "index.html": 200, "repositories.html": 200, "repo.html": 200,
        "pr.html": 200, "review.html": 200, "audit.html": 200,
        "error.html": 404,
    }, statuses

    broken = []
    for name, resp in rendered.items():
        nonce = _csp(resp)["script-src"].split("'nonce-")[1].split("'")[0]
        tags = re.findall(r"<script\b[^>]*>", resp.text)
        if not tags:
            broken.append(f"{name}: rendered no script tag at all ({resp.status_code})")
            continue
        for tag in tags:
            if f'nonce="{nonce}"' not in tag:
                broken.append(f"{name} ({resp.status_code}): {tag}")

    assert broken == [], "scripts the CSP would block:\n  " + "\n  ".join(broken)


def test_the_referrer_policy_leaves_a_same_origin_referer_intact(client):
    """no-referrer broke the audit button in production, and this is why.

    Azure Container Apps' EasyAuth runs its own anti-forgery check on an
    AUTHENTICATED non-GET request, and that check is REFERER-BASED. Step 9
    set Referrer-Policy: no-referrer, so the browser stopped sending one, so
    every signed-in POST was refused with 403 and an empty body BEFORE
    reaching this application. Measured on the deployed build, same session,
    same route, only the Referer differing:

        no Referer          -> 403, empty, never reaches the app
        Referer, full URL   -> 405 (i.e. reaches the app)
        Referer, origin only-> 405

    And the history confirms the cause rather than merely fitting it: POSTs
    to the audit route returned 404 on every revision BEFORE step 9 (they
    reached the app and were refused by the identity bug) and 403 on every
    revision after it. The button never worked, for two different reasons in
    sequence.

    same-origin, NOT strict-origin-when-cross-origin. Both satisfy EasyAuth,
    because both send a Referer on a same-origin request. The difference is
    what leaks: strict-origin-when-cross-origin still sends the ORIGIN to
    third parties, which tells any site linked from a report that this
    deployment exists. same-origin sends them nothing at all, which keeps
    step 9's actual privacy goal -- dashboard URLs carry owner, repo and PR
    number -- while restoring the header our own infrastructure depends on.
    """
    resp = _dashboard(client)

    assert resp.headers["referrer-policy"] == "same-origin"
    # The two that must not come back: one breaks the button, the other
    # leaks the origin to every external link.
    assert resp.headers["referrer-policy"] != "no-referrer"
    assert resp.headers["referrer-policy"] != "strict-origin-when-cross-origin"


# --------------------------------------------------------------------------
# Cache-Control on signed-in pages
# --------------------------------------------------------------------------
#
# Purely additive. The repositories page showed a finished audit's row
# without "last: done" on localhost, and the server rendered it correctly
# when asked again -- which leaves a browser-held copy of the page as the
# remaining explanation. Pages behind sign-in are per-viewer and change
# under the viewer, so no copy of one should be reused.

# The CSP and Referrer-Policy exactly as they shipped before Cache-Control
# was added. Byte-for-byte, so that "add one header" cannot quietly become
# "and also adjust the policy" in the same change.
_CSP_BEFORE_CACHE_CONTROL = (
    "default-src 'none'; script-src 'self' 'nonce-NONCE'; "
    "style-src 'self' https://fonts.googleapis.com; style-src-attr 'unsafe-inline'; "
    "font-src https://fonts.gstatic.com; img-src 'self'; connect-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
)


def test_the_csp_and_referrer_policy_are_byte_for_byte_unchanged(client):
    from codeguard.api.headers import policy

    assert policy("NONCE") == _CSP_BEFORE_CACHE_CONTROL
    resp = _dashboard(client)
    nonce = _csp(resp)["script-src"].split("'nonce-")[1].rstrip("'")
    assert resp.headers["content-security-policy"] == _CSP_BEFORE_CACHE_CONTROL.replace("NONCE", nonce)
    assert resp.headers["referrer-policy"] == "same-origin"


def test_signed_in_pages_are_never_cached(client):
    resp = _dashboard(client)
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"


def test_signed_in_json_is_never_cached_either(client):
    """The search index and the audit poll are per-viewer too."""
    with patch.object(access, "installed_repositories", return_value=[]), \
         patch.object(access, "_is_collaborator", return_value=True):
        resp = client.get("/dashboard/search")
    assert resp.headers.get("cache-control") == "no-store"


def test_static_assets_and_machine_endpoints_keep_their_caching(client):
    """no-store is for per-viewer pages. A stylesheet is the same for
    everybody, and a probe is not a browser."""
    assert "cache-control" not in client.get("/static/dashboard.css").headers or \
        client.get("/static/dashboard.css").headers["cache-control"] != "no-store"
    assert client.get("/health").headers.get("cache-control") != "no-store"
