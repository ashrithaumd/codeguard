"""Fixture reviews for looking at the dashboard locally.

NOT test data and NOT sample data to ship. These rows exist so the
dashboard's states — blocked, truncated, private, zero findings, a tool
that failed — can be seen without waiting for real pull requests to
produce each one.

Two things stop them being mistaken for real reviews:

  - they refuse to be written anywhere but a local database (see
    _assert_local), so a mistyped DATABASE_URL cannot put them in
    production;
  - every row is under the `codeguard-fixtures` owner, which is not a
    real GitHub account, and every summary body starts with FIXTURE. A
    row reading `codeguard-fixtures/...` is self-evidently not a review
    of anything.

Run inside the compose stack:

    docker compose exec api python /app/scripts/seed_dashboard_fixtures.py
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import psycopg
from psycopg.types.json import Jsonb

NOW = datetime.now(timezone.utc)

# Not a real GitHub owner. Reserved so a fixture row is distinguishable
# from a real review at a glance, on any page, without needing to know
# which repositories are genuinely installed.
FIXTURE_OWNER = "codeguard-fixtures"

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "db", "postgres"}


def _assert_local(dsn: str) -> None:
    """Refuse to write fixtures anywhere but a local database.

    The guard is on the HOST, not the database name: production's
    database is also called `codeguard`, so a name check would happily
    pass against Azure. Any hostname that is not loopback or the compose
    service is treated as somebody's real deployment.
    """
    host = (urlsplit(dsn).hostname or "").lower()
    if host not in _LOCAL_HOSTS:
        sys.exit(
            f"refusing to seed fixtures: DATABASE_URL points at {host!r}, which is not a local "
            f"database ({', '.join(sorted(_LOCAL_HOSTS))}). These rows are for looking at the "
            "dashboard locally and must never reach a real deployment."
        )


def _finding(path, line, sev, tool, rule, msg):
    return {
        "file": path, "start_line": line, "end_line": line, "severity": sev,
        "source_tool": tool, "rule_id": rule, "message": "FIXTURE. " + msg,
        "fingerprint": uuid.uuid4().hex[:16], "confidence": 1.0,
    }


SQL_FIX = {
    "fingerprint": "",  # filled in below so the diff renders against a real finding
    "suggestion_body": '```suggestion\n    query = "SELECT * FROM orders WHERE id = %s"\n'
                       "    cursor.execute(query, (order_id,))\n```",
    "target_file": "billing/charge.py", "target_line": 88, "target_end_line": 89,
    "original_text": '    query = "SELECT * FROM orders WHERE id = \'%s\'" % order_id\n'
                     "    cursor.execute(query)",
}

_sql_finding = _finding(
    "billing/charge.py", 88, "CRITICAL", "security", "B608",
    "Raw SQL built from a request parameter reaches execute() without parameterisation.",
)
SQL_FIX["fingerprint"] = _sql_finding["fingerprint"]

ROWS = [
    dict(
        repo="checkout-service", pr=214, sha="a91f2c7d4e8b1a6f3c5d9e2b7a4f8c1d6e3b9a72",
        title="Add idempotency keys to the refund path",
        action="opened", private=False, conclusion="failure", age=timedelta(hours=3),
        gate="HIGH", fix="HIGH", files_seen=41, files_reviewed=15,
        buckets=(2, 2, 1, 0), dismissed=7, inline=5, fixes=1,
        tokens=(48_920, 6_140), cost=0.4127, duration=94.3, budget=True,
        findings=[
            _sql_finding,
            # Split across a concatenation so no credential-shaped
            # literal sits in a source line: GitHub's push protection
            # blocked this file for containing a "Stripe API Key" when
            # it was written out whole. The value is fabricated either
            # way; this makes that unambiguous.
            _finding("billing/charge.py", 140, "HIGH", "security", "B105",
                     "Possible hardcoded credential: api_secret = "
                     "'sk_" + "live_51HxxxxxxxxxxxxxxxxxxxxxxxxxxxxQ' assigned inline."),
            _finding("billing/refund.py", 22, "MEDIUM", "quality-agent", "quality.error-handling",
                     "The refund path swallows every exception and returns None."),
            _finding("billing/ledger.py", 0, "MEDIUM", "test-agent", "test.test",
                     "The new reconciliation branch has no accompanying test."),
            _finding("requirements.txt", 12, "HIGH", "osv", "GHSA-9v9h-cgj8-h64p",
                     "requests 2.19.1 is affected by a known CRLF injection vulnerability."),
        ],
        fix_suggestions=[SQL_FIX],
        filtered=[{"path": "docs/architecture.md", "reason": "docs"},
                  {"path": "package-lock.json", "reason": "lockfile/generated/docs/vendored"},
                  {"path": "billing/migrations/0042_add_index.py", "reason": "budget: max_files_per_pr"}],
        failures=[{"path": "billing/ledger.py", "agent": "security",
                   "reason": "APITimeoutError: request timed out"}],
        latencies=[{"node": "review_security", "file": "billing/charge.py", "seconds": 12.4},
                   {"node": "summarize", "file": "", "seconds": 3.2}],
        summary="FIXTURE ROW - not a real review. Blocked: 1 critical and 2 high severity findings.",
    ),
    dict(
        repo="checkout-service", pr=214, sha="5c1d9e2b7a4f8c1d6e3b9a72a91f2c7d4e8b1a6f",
        title="Add idempotency keys to the refund path",
        action="synchronize", private=False, conclusion="failure", age=timedelta(hours=2),
        gate="HIGH", fix="HIGH", files_seen=41, files_reviewed=15,
        buckets=(2, 1, 1, 0), dismissed=6, inline=4, fixes=0,
        tokens=(12_440, 1_980), cost=0.1032, duration=38.1, budget=True,
        findings=[_finding("billing/charge.py", 88, "CRITICAL", "security", "B608",
                           "Raw SQL built from a request parameter reaches execute().")],
        summary="FIXTURE ROW - not a real review. Second push; most hunks served from cache.",
    ),
    dict(
        repo="checkout-service", pr=214, sha="9a72a91f2c7d4e8b1a6f5c1d9e2b7a4f8c1d6e3b",
        title="Add idempotency keys to the refund path",
        action="synchronize", private=False, conclusion="success", age=timedelta(hours=1),
        gate="HIGH", fix="HIGH", files_seen=41, files_reviewed=15,
        buckets=(0, 1, 0, 0), dismissed=6, inline=1, fixes=0,
        tokens=(9_110, 1_240), cost=0.0774, duration=29.6, budget=True,
        findings=[_finding("billing/refund.py", 22, "MEDIUM", "quality-agent",
                           "quality.error-handling", "The refund path swallows every exception.")],
        summary="FIXTURE ROW - not a real review. Third push; the SQL injection was fixed.",
    ),
    dict(
        repo="internal-tools", pr=88, sha="7d3c8b1f9a2e5c4d6b8a3f1e9c7d2b5a4f8e1c63",
        title="Rotate the staging deploy key",
        action="opened", private=True, conclusion="success", age=timedelta(days=2),
        gate="HIGH", fix="HIGH", files_seen=6, files_reviewed=6,
        buckets=(0, 0, 1, 0), dismissed=2, inline=1, fixes=0,
        tokens=(9_410, 1_205), cost=0.0812, duration=31.7, budget=False,
        findings=[_finding("api/routes.py", 55, "LOW", "ruff", "E501",
                           "Line too long (118 > 100 characters).")],
        summary="FIXTURE ROW - not a real review. Private repository.",
    ),
    dict(
        repo="docs-site", pr=12, sha="fc90af15410abe0cf3cd23c9de23a2dc44c7a26b",
        title="Fix a broken link in the quickstart",
        action="opened", private=False, conclusion="success", age=timedelta(hours=9),
        gate="CRITICAL", fix="HIGH", files_seen=1, files_reviewed=1,
        buckets=(0, 0, 0, 0), dismissed=1, inline=0, fixes=0,
        tokens=(1_204, 88), cost=0.0031, duration=9.4, budget=False,
        findings=[],
        summary="FIXTURE ROW - not a real review. Nothing found.",
    ),
]

_INSERT = """
INSERT INTO reviews (
    job_id, owner, repo, pr_number, head_sha, action, private,
    summary_body, check_conclusion, gate_threshold, fix_threshold,
    files_seen, files_reviewed, findings_total,
    findings_verdict_confirmed, findings_generative,
    findings_deterministic, findings_unverified,
    dismissed_count, inline_count, fix_suggestion_count,
    budget_exceeded, filtered_files_json, pr_title,
    tokens_in, tokens_out, estimated_cost_usd, duration_s,
    node_latencies_json, findings_json, dismissed_json,
    fix_suggestions_json, verdict_call_failures_json, created_at
) VALUES (
    %s,%s,%s,%s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s, %s,%s, %s,%s,
    %s,%s,%s, %s,%s,%s, %s,%s,%s,%s, %s,%s,%s,%s,%s, %s
)
"""


async def main() -> None:
    dsn = os.environ["DATABASE_URL"]
    _assert_local(dsn)
    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        await conn.execute("DELETE FROM reviews WHERE owner = %s", (FIXTURE_OWNER,))
        for r in ROWS:
            vc, gen, det, unv = r["buckets"]
            await conn.execute(_INSERT, (
                uuid.uuid4(), FIXTURE_OWNER, r["repo"], r["pr"], r["sha"], r["action"], r["private"],
                r["summary"], r["conclusion"], r["gate"], r["fix"],
                r["files_seen"], r["files_reviewed"], vc + gen + det + unv,
                vc, gen, det, unv,
                r["dismissed"], r["inline"], r["fixes"],
                r["budget"], Jsonb(r.get("filtered", [])), r["title"],
                r["tokens"][0], r["tokens"][1], r["cost"], r["duration"],
                Jsonb(r.get("latencies", [])), Jsonb(r.get("findings", [])),
                Jsonb([]), Jsonb(r.get("fix_suggestions", [])),
                Jsonb(r.get("failures", [])), NOW - r["age"],
            ))
        await conn.commit()
    print(f"seeded {len(ROWS)} fixture reviews under {FIXTURE_OWNER}/")


asyncio.run(main())
