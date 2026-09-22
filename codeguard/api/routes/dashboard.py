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
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from codeguard.api import dashboard_queries as q
from codeguard.api.access import can_view, visible_private_repos
from codeguard.api.auth import client_principal
from codeguard.api.redact import redact

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_PACKAGE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = _PACKAGE_DIR / "templates"
STATIC_DIR = _PACKAGE_DIR / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Registered as a filter rather than applied in each route, so a new
# template that renders a stored string gets redaction by writing
# `|redact` instead of by remembering a helper exists. See
# codeguard/api/redact.py for why any of this is needed.
templates.env.filters["redact"] = redact

PAGE_SIZE = 50


async def _visible_repos(pool, principal: str | None) -> list[tuple[str, str]]:
    return visible_private_repos(await q.distinct_private_repos(pool), principal)


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
    allowed = await _visible_repos(pool, principal)
    filters = q.Filters(repo=repo, severity=severity, gate=gate,
                        date_from=date_from, date_to=date_to)

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
    if review is None or not can_view(
        owner=review["owner"], repo=review["repo"],
        private=review["private"], principal=principal,
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
    if not can_view(
        owner=owner, repo=repo,
        private=any(r["private"] for r in reviews), principal=principal,
    ):
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
    if not reviews or not can_view(
        owner=owner, repo=repo,
        private=any(r["private"] for r in reviews), principal=principal,
    ):
        raise HTTPException(status_code=404, detail="pull request not found")

    return _page(request, "pr.html", principal,
                 owner=owner, repo=repo, pr_number=pr_number, reviews=reviews)
