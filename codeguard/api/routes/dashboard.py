"""The review dashboard: three server-rendered pages over the `reviews`
table.

Rendering rules, from migrations/006's own SECURITY block:

  EVERY TEXT/JSONB FIELD IN THIS TABLE MUST BE HTML-ESCAPED BEFORE IT IS
  RENDERED ANYWHERE.

Jinja2 is configured with autoescape on, and no template in this package
uses `|safe` on stored data. `summary_body` in particular is Markdown
that GitHub rendered inside its own sandbox with its own sanitiser; we
do not inherit that, so it is shown as escaped text rather than parsed
as HTML. Finding messages are worse still — Finding.message is
tool-generated but echoes fragments of the scanned code (Bandit's
hardcoded-secret message literally contains the matched string), i.e.
text a PR author controls.

404, never 403, for a review the visitor may not see. A 403 confirms
the review exists, which tells an anonymous visitor that a given repo
and PR number are being reviewed — exactly what a private repo is
hiding.
"""

from __future__ import annotations

import logging
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from codeguard.api import access, audits
from codeguard.api import dashboard_queries as q
from codeguard.api.auth import client_principal
from codeguard.config import get_settings
from codeguard.queue.queue import enqueue
from codeguard.redact import redact

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_PACKAGE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = _PACKAGE_DIR / "templates"
STATIC_DIR = _PACKAGE_DIR / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Registered as a filter rather than applied in each route, so a new
# template that renders a stored string gets redaction by writing
# `|redact` instead of by remembering a helper exists. See
# codeguard/redact.py for why any of this is needed.
templates.env.filters["redact"] = redact

PAGE_SIZE = 50


async def _visible_repos(pool, principal: str | None) -> list[tuple[str, str]]:
    """Every repo with reviews that this visitor may see. Public included.

    Was `visible_private_repos(distinct_private_repos(...))` — only
    private repos were ever checked, because the SQL clause let public
    ones through unconditionally. Both halves moved together: the
    candidate set is now every repo with a review row, and every one of
    them is asked about.

    Anonymous short-circuits to [] inside accessible_repos, so an
    unauthenticated page view still makes no GitHub calls at all — and []
    now means FALSE in _visibility_clause rather than "public only".
    """
    candidates = [(owner, repo) for owner, repo, _private in await q.distinct_repos(pool)]
    return sorted(await access.accessible_repos(candidates, principal))


def asset_version() -> str:
    """Cache-busting token for the stylesheet, from its own mtime.

    StaticFiles serves with a far-future-ish cache, so without this an
    edited stylesheet keeps rendering with the previous one until a hard
    reload — which during development reads as "the CSS change did
    nothing". Derived rather than hand-bumped, because a hand-bumped
    version is one someone forgets.
    """
    try:
        return str(int((STATIC_DIR / "dashboard.css").stat().st_mtime))
    except OSError:
        return "0"


def _page(request: Request, name: str, principal: str | None, **context) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request, name=name,
        context={"principal": principal, "asset_version": asset_version(), **context},
    )


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    page: int = Query(1, ge=1),
    repo: str = Query(""),
    severity: str = Query(""),
    gate: str = Query(""),
    date_from: str = Query("", alias="from"),
    date_to: str = Query("", alias="to"),
) -> HTMLResponse:
    """Filters live in the query string so a filtered view is a URL —
    bookmarkable, shareable, and survivable across a reload. An
    unrecognised filter value is dropped rather than rejected (see
    Filters), because a stale bookmark should degrade to the unfiltered
    page rather than to an error.
    """
    pool = request.app.state.pool
    principal = client_principal(request)
    filters = q.Filters(repo=repo, severity=severity, gate=gate,
                        date_from=date_from, date_to=date_to)

    # Signed-in landing view is the control panel, not the log.
    #
    # Conditional on there being NO query string, which is what makes
    # this safe for existing links: every filtered, paged or shared
    # dashboard URL carries parameters, so only a bare visit to
    # /dashboard is redirected. A blanket redirect would silently drop
    # the filters off a bookmark, which is the whole reason filters were
    # put in the query string in the first place.
    if principal and not request.query_params:
        return RedirectResponse(url="/dashboard/repos", status_code=302)

    allowed = await _visible_repos(pool, principal)

    offset = (page - 1) * PAGE_SIZE
    reviews = await q.list_reviews(pool, principal_repos=allowed, limit=PAGE_SIZE,
                                   offset=offset, filters=filters)
    agg = await q.totals(pool, principal_repos=allowed, filters=filters)
    total = agg.get("reviews", 0)
    # The repo picker lists every repo the visitor can see, NOT the
    # filtered set — a picker that hid the option you would switch to
    # would strand you on whatever you picked first.
    all_repos = await q.list_repos(pool, principal_repos=allowed)
    repos = await q.list_repos(pool, principal_repos=allowed, filters=filters)

    return _page(
        request, "index.html", principal,
        reviews=reviews, repos=repos, all_repos=all_repos, total=total, totals=agg,
        page=page, page_size=PAGE_SIZE, has_next=offset + len(reviews) < total,
        filters=filters, severities=q.SEVERITIES,
    )


@router.get("/search")
async def search(request: Request) -> JSONResponse:
    """Everything the quick-jump palette matches against, as JSON.

    Sent whole, once, rather than queried per keystroke: the dataset is
    one row per repo and per pull request, so matching locally is
    instant and a request per keystroke is not. Visibility-filtered like
    every other query, so it can never surface a private repo's name —
    or a PR title — to someone who could not open the page anyway.
    """
    pool = request.app.state.pool
    principal = client_principal(request)
    allowed = await _visible_repos(pool, principal)
    index = await q.search_index(pool, principal_repos=allowed)

    return JSONResponse({
        "repos": [
            {"owner": r["owner"], "repo": r["repo"],
             "url": f"/dashboard/repos/{r['owner']}/{r['repo']}"}
            for r in index["repos"]
        ],
        "pulls": [
            {"owner": p["owner"], "repo": p["repo"], "number": p["pr_number"],
             "title": p["pr_title"] or "",
             "url": f"/dashboard/repos/{p['owner']}/{p['repo']}/pulls/{p['pr_number']}"}
            for p in index["pulls"]
        ],
        "files": [
            {"path": f["path"], "repo": f"{f['owner']}/{f['repo']}",
             "url": f"/dashboard/reviews/{f['job_id']}"}
            for f in index["files"]
        ],
    })


@router.get("/reviews/{job_id}", response_class=HTMLResponse)
async def review_detail(request: Request, job_id: UUID) -> HTMLResponse:
    pool = request.app.state.pool
    principal = client_principal(request)

    review = await q.get_review(pool, job_id)
    # Both branches answer 404, deliberately and identically: "no such
    # review" and "not yours" must be indistinguishable from outside.
    # can_access_repo, not can_view: a review page carries the PR title,
    # the findings and the spend. Public code does not make those public.
    if review is None or not access.can_access_repo(
        review["owner"], review["repo"], principal,
    ):
        raise HTTPException(status_code=404, detail="review not found")

    # Siblings for previous/next. Scoped to this pull request, because
    # "the next review" only means something within one PR — across a
    # repo it is just whatever happened to be reviewed next.
    siblings = await q.pr_history(
        pool, owner=review["owner"], repo=review["repo"], pr_number=review["pr_number"],
    )
    ids = [r["job_id"] for r in siblings]
    here = ids.index(job_id) if job_id in ids else -1
    # siblings is newest-first, so the NEWER neighbour is the lower index.
    newer = siblings[here - 1] if here > 0 else None
    older = siblings[here + 1] if 0 <= here < len(siblings) - 1 else None

    return _page(request, "review.html", principal, review=review,
                 newer=newer, older=older, sibling_count=len(siblings),
                 position=(here + 1) if here >= 0 else None)


@router.get("/repos/{owner}/{repo}", response_class=HTMLResponse)
async def repo_detail(request: Request, owner: str, repo: str) -> HTMLResponse:
    pool = request.app.state.pool
    principal = client_principal(request)

    reviews = await q.repo_history(pool, owner=owner, repo=repo)
    if not reviews:
        raise HTTPException(status_code=404, detail="repo not found")

    # ANY private row in the history gates the whole page, not just the
    # newest one. This page lists every review it fetched, so asking only
    # the newest row would publish a repo's entire private history the
    # moment it was made public — the rows recorded while it was private
    # included. Visibility is per-row because it is recorded per-row
    # (migrations/007), so the strictest row is the one that answers.
    # The per-row `any(private)` rule is gone because it is subsumed: the
    # question is no longer "is any row private" but "may this person see
    # this repository at all", which is strictly stronger and does not
    # depend on what the rows happen to say.
    if not access.can_access_repo(owner, repo, principal):
        raise HTTPException(status_code=404, detail="repo not found")

    pulls = await q.pr_summaries(pool, owner=owner, repo=repo)
    return _page(request, "repo.html", principal,
                 owner=owner, repo=repo, reviews=reviews, pulls=pulls)


@router.get("/repos/{owner}/{repo}/pulls/{pr_number}", response_class=HTMLResponse)
async def pr_detail(request: Request, owner: str, repo: str, pr_number: int) -> HTMLResponse:
    """One pull request's review history.

    The only grouping where a cost-over-time chart means anything: every
    point is the same pull request, so the differences between them are
    about the reviews rather than about which PR happened to be next.
    """
    pool = request.app.state.pool
    principal = client_principal(request)

    reviews = await q.pr_history(pool, owner=owner, repo=repo, pr_number=pr_number)
    if not reviews or not access.can_access_repo(owner, repo, principal):
        raise HTTPException(status_code=404, detail="pull request not found")

    return _page(request, "pr.html", principal,
                 owner=owner, repo=repo, pr_number=pr_number, reviews=reviews)


# Audit mode produces no fix suggestions. Stated in the UI rather than
# left to be discovered: propose_fix runs per-hunk against a diff, and an
# audit has no diff — it reviews whole files, so there is no
# before/after pair for a suggestion to be anchored to. Someone who has
# seen fix suggestions on a pull request will otherwise read their
# absence here as a failure.
AUDIT_NO_FIXES_NOTE = (
    "Audit mode reports findings only — no fix suggestions. "
    "Fixes are anchored to a pull request's diff, and an audit has no diff."
)

# Why the button is absent on a private repository. run_audit clones over
# HTTPS and would need a credential in the URL to reach a private repo;
# it also prints the target to stderr and puts git's own stderr (URL
# included) into the error it stores and renders. An installation token
# passed that way would end up in the worker's logs and on this page.
PRIVATE_AUDIT_NOTE = (
    "Private repositories cannot be audited yet: the audit clones over HTTPS, "
    "and the clone URL appears in logs and error messages."
)


def _audit_target(owner: str, repo: str) -> str:
    return f"https://github.com/{owner}/{repo}"


@router.get("/repos", response_class=HTMLResponse)
async def repositories(request: Request) -> HTMLResponse:
    """Every repository CodeGuard is installed on THAT THIS VISITOR CAN
    ACCESS, with its activity.

    Two independent sources, ANDed:

      access.installed_repositories()  -> is CodeGuard active here
      access.can_access_repo()         -> may this visitor see it exists

    ACCESS RULE, and why it is not can_view's: this page originally passed
    each row through can_view(private=entry["private"], ...), which reads
    correctly and was wrong. can_view short-circuits to True on
    `not private`, because a review of public code is public information.
    An INSTALLATION LIST is not. That these particular public repos are
    the ones someone chose to run a code reviewer over is a fact about the
    operator, published by nobody -- and the old call leaked all nine of
    them, by name and with review counts and costs, to anonymous visitors
    on a public URL.

    So:

      anonymous  -> nothing. Not a filtered list, not a count, not
                    "installed 9". installed_repositories() is not even
                    called, so there is no list in memory to leak through
                    a future template edit, and an unauthenticated page
                    view still costs zero GitHub calls.
      signed in  -> can_access_repo per row, which is can_view with
                    private=True: the same collaborator call and the same
                    cache, asked for every row regardless of visibility.

    A repo with no reviews still appears, with zeroed stats — "installed
    but never reviewed" is a real and interesting state (it usually means
    no pull request has been opened yet), and hiding those rows would
    make the page disagree with GitHub's own installation settings.
    """
    pool = request.app.state.pool
    principal = client_principal(request)
    settings = get_settings()

    # Before any lookup. An anonymous visitor gets the sign-in prompt and
    # no data of any kind, so this returns before the installation list is
    # fetched rather than fetching it and filtering to nothing.
    if not principal:
        return _page(
            request, "repositories.html", principal,
            rows=[], may_audit=False, lookup_failed=False, signed_out=True,
            settings_url=access.installation_settings_url(None),
            audit_note=AUDIT_NO_FIXES_NOTE, private_note=PRIVATE_AUDIT_NOTE,
        )

    lookup_failed = False
    installed: list[dict] = []
    try:
        installed = access.installed_repositories()
    except access.InstallationLookupFailed:
        # Fail closed on the INSTALLED question, not on the page. We do
        # not invent repositories we could not confirm; we fall back to
        # the ones that have review rows, which are visibility-filtered
        # by the same gate and disclose nothing new. The banner says the
        # list is partial, because an empty page here would otherwise
        # read as "you have not installed CodeGuard anywhere".
        lookup_failed = True

    stats = await audits.repo_stats(pool)
    latest_audits = await audits.latest_per_repo(pool)

    if lookup_failed:
        known = await q.distinct_repos(pool)
        installed = [
            {"owner": owner, "repo": name, "private": private,
             "installation_id": None, "html_url": f"https://github.com/{owner}/{name}"}
            for owner, name, private in known
        ]

    may_audit = settings.may_trigger_audit(principal)
    rows = []
    for entry in installed:
        owner, name = entry["owner"], entry["repo"]
        # can_access_repo, NOT can_view(private=entry["private"]). The
        # latter waves every public repo through for any signed-in
        # visitor, which is the leak this page had.
        if not access.can_access_repo(owner, name, principal):
            continue
        stat = stats.get((owner, name), {})
        audit = latest_audits.get((owner, name))
        rows.append({
            **entry,
            "active": not lookup_failed,
            "review_count": stat.get("review_count", 0),
            "last_reviewed": stat.get("last_reviewed"),
            "total_cost": float(stat.get("total_cost", 0) or 0),
            "audit": audit,
            "audit_in_flight": bool(audit and audit["status"] in ("queued", "running")),
            # Both conditions, so the template never has to combine them
            # and get it wrong. The POST re-checks may_trigger_audit
            # regardless of what this said.
            "can_audit": may_audit and not entry["private"],
        })

    rows.sort(key=lambda r: (r["last_reviewed"] is None, -(r["review_count"]), r["repo"]))

    return _page(
        request, "repositories.html", principal,
        rows=rows, may_audit=may_audit, lookup_failed=lookup_failed,
        settings_url=access.installation_settings_url(
            next((r["installation_id"] for r in rows if r["installation_id"]), None)
        ),
        audit_note=AUDIT_NO_FIXES_NOTE, private_note=PRIVATE_AUDIT_NOTE,
    )


@router.post("/repos/{owner}/{repo}/audit")
async def trigger_audit(request: Request, owner: str, repo: str):
    """Enqueue an audit. Owner-gated, and the gate is HERE.

    The repositories page hides the button for everyone else, but a
    hidden button is a UI affordance and this route is reachable by curl.
    settings.may_trigger_audit is the actual authority, and it defaults
    to nobody.

    404 rather than 403 for an unauthorised caller, consistent with the
    rest of this module: a 403 would confirm the route exists and that
    an audit facility is there to be found.
    """
    pool = request.app.state.pool
    principal = client_principal(request)
    settings = get_settings()

    if not settings.may_trigger_audit(principal):
        logger.warning("audit refused for principal=%r on %s/%s", principal, owner, repo)
        raise HTTPException(status_code=404, detail="not found")

    entry = next(
        (e for e in _installed_or_empty() if (e["owner"], e["repo"]) == (owner, repo)), None,
    )
    private = entry["private"] if entry else True
    if not access.can_access_repo(owner, repo, principal):
        raise HTTPException(status_code=404, detail="not found")
    if private:
        # Not a permission failure — a capability one. See
        # PRIVATE_AUDIT_NOTE.
        raise HTTPException(status_code=400, detail=PRIVATE_AUDIT_NOTE)

    try:
        audit = await audits.request_audit(
            pool, owner=owner, repo=repo, requested_by=principal, private=private,
        )
    except audits.AuditInFlight as inflight:
        # Not an error. The user asked for an audit of this repo and
        # there already is one, so they are sent to watch it rather than
        # told off — and, critically, no second job is enqueued and no
        # second lot of Anthropic credit is spent.
        return RedirectResponse(
            url=f"/dashboard/audits/{inflight.existing['id']}", status_code=303,
        )

    job, created = await enqueue(
        pool, type="repo_audit",
        payload={"audit_id": str(audit["id"]), "owner": owner, "repo": repo,
                 "target": _audit_target(owner, repo)},
        # The audit id, so the queue's own idempotency matches the
        # request's identity. The in-flight index already prevents a
        # duplicate request; this prevents a duplicate JOB for one
        # request, e.g. a retried POST that got past the index because
        # the row was already committed.
        idempotency_key=f"repo_audit:{audit['id']}",
    )
    await audits.attach_job(pool, audit["id"], job.id)
    logger.info("audit %s enqueued for %s/%s by %s (job=%s, created=%s)",
                audit["id"], owner, repo, principal, job.id, created)

    return RedirectResponse(url=f"/dashboard/audits/{audit['id']}", status_code=303)


def _installed_or_empty() -> list[dict]:
    try:
        return access.installed_repositories()
    except access.InstallationLookupFailed:
        return []


async def _audit_or_404(request: Request, audit_id: UUID) -> dict:
    """Fetch an audit the visitor is allowed to see, or 404.

    Same visibility rule as a review, from the flag recorded on the audit
    row at request time — and the same deliberate conflation of "no such
    audit" with "not yours", so the response cannot be used to discover
    that a given repo is being audited.
    """
    pool = request.app.state.pool
    principal = client_principal(request)
    audit = await audits.get_audit(pool, audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="audit not found")
    if not access.can_access_repo(audit["owner"], audit["repo"], principal):
        raise HTTPException(status_code=404, detail="audit not found")
    return audit


@router.get("/audits/{audit_id}.json")
async def audit_status(request: Request, audit_id: UUID) -> JSONResponse:
    """What the page polls.

    Polling rather than SSE or a websocket: the api is pinned to a single
    replica, an audit is measured in minutes not milliseconds, and a
    long-lived connection through EasyAuth and the Container Apps ingress
    is more failure surface than a 2-second GET. The page stops polling
    on a terminal status, so a finished audit costs nothing.

    Deliberately does NOT include report_markdown. The report can be tens
    of kilobytes and the poller only needs to know whether to reload;
    sending it on every tick would make a 2-second poll expensive in
    exactly the case where the answer has not changed.
    """
    audit = await _audit_or_404(request, audit_id)
    return JSONResponse({
        "id": str(audit["id"]),
        "status": audit["status"],
        "terminal": audit["status"] in audits.TERMINAL,
        "error": audit["error"],
        "exit_code": audit["exit_code"],
        "duration_s": audit["duration_s"],
    })


@router.get("/audits/{audit_id}", response_class=HTMLResponse)
async def audit_detail(request: Request, audit_id: UUID) -> HTMLResponse:
    audit = await _audit_or_404(request, audit_id)
    principal = client_principal(request)
    return _page(request, "audit.html", principal, audit=audit,
                 audit_note=AUDIT_NO_FIXES_NOTE)
