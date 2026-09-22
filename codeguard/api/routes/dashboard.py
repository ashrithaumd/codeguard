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
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from codeguard.api import dashboard_queries as q
from codeguard.api.access import can_view, visible_private_repos
from codeguard.api.auth import client_principal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_PACKAGE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = _PACKAGE_DIR / "templates"
STATIC_DIR = _PACKAGE_DIR / "static"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

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
async def index(request: Request, page: int = Query(1, ge=1)) -> HTMLResponse:
    pool = request.app.state.pool
    principal = client_principal(request)
    allowed = await _visible_repos(pool, principal)

    offset = (page - 1) * PAGE_SIZE
    reviews = await q.list_reviews(pool, principal_repos=allowed, limit=PAGE_SIZE, offset=offset)
    total = await q.count_reviews(pool, principal_repos=allowed)
    repos = await q.list_repos(pool, principal_repos=allowed)

    return _page(
        request, "index.html", principal,
        reviews=reviews, repos=repos, total=total, page=page,
        page_size=PAGE_SIZE, has_next=offset + len(reviews) < total,
    )


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

    return _page(request, "review.html", principal, review=review)


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

    return _page(request, "repo.html", principal, owner=owner, repo=repo, reviews=reviews)
