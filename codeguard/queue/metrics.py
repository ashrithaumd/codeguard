"""Prometheus metrics for queue state, computed *live* from Postgres, not
tracked via in-process counters that could drift from reality (a process
restart zeroes an in-memory counter; the DB's actual row counts never
lie). refresh_live_gauges() is called synchronously from the /metrics
handler on every scrape, so what Prometheus sees is always the true
state as of that exact request, never a stale snapshot.

Ported from Reliqueue's api/metrics.py, translated to psycopg3.
"""

from __future__ import annotations

from prometheus_client import Gauge
from psycopg_pool import AsyncConnectionPool

QUEUE_DEPTH = Gauge(
    "codeguard_queue_depth",
    "Current number of jobs by status",
    ["status"],
)

ACTIVE_LEASES = Gauge(
    "codeguard_queue_active_leases",
    "Jobs currently leased whose lease has NOT yet expired. Deliberately "
    "distinct from queue_depth{status='leased'}: a job can be "
    "status='leased' in the DB while already past leased_until, orphaned "
    "and just waiting for the reaper's next sweep. A growing gap between "
    "the two is a leading indicator of workers dying faster than the "
    "reaper is keeping up.",
)

DEAD_LETTER_DEPTH = Gauge(
    "codeguard_queue_dead_letter_depth",
    "Current number of rows in dead_letters",
)

_ALL_STATUSES = ("pending", "leased", "done", "dead")


async def refresh_live_gauges(pool: AsyncConnectionPool) -> None:
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT status, count(*) AS n FROM jobs GROUP BY status")
            status_rows = await cur.fetchall()
            await cur.execute("SELECT count(*) AS n FROM jobs WHERE status = 'leased' AND leased_until >= now()")
            active_leases = (await cur.fetchone())["n"]
            await cur.execute("SELECT count(*) AS n FROM dead_letters")
            dead_letter_depth = (await cur.fetchone())["n"]

    counts = {r["status"]: r["n"] for r in status_rows}
    for status in _ALL_STATUSES:
        QUEUE_DEPTH.labels(status=status).set(counts.get(status, 0))
    ACTIVE_LEASES.set(active_leases)
    DEAD_LETTER_DEPTH.set(dead_letter_depth)
