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
  * Referrer-Policy no-referrer: dashboard URLs contain owner, repo and
    PR number. Following an external link from a report should not hand
    those to the destination.
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
    assert resp.headers["referrer-policy"] == "no-referrer"


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
