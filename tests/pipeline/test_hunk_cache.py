"""Regression coverage for codeguard.pipeline.hunk_cache against a real
Postgres — the VALUES-list query in fetch_cache_hits is exactly the
kind of thing not worth trusting without actually running it (see
tests/pipeline/conftest.py's `pool` fixture).
"""

from __future__ import annotations

from codeguard.pipeline.hunk_cache import fetch_cache_hits, write_cache_records
from codeguard.pipeline.models import CacheWriteRecord
from tests.pipeline.conftest import make_finding


async def test_fetch_cache_hits_empty_when_nothing_written(pool):
    hits = await fetch_cache_hits(pool, "o", "r", [("a.py", "hash1", "security")])
    assert hits == {}


async def test_fetch_cache_hits_empty_keys_short_circuits_with_no_query(pool):
    hits = await fetch_cache_hits(pool, "o", "r", [])
    assert hits == {}


async def test_write_then_fetch_round_trips_findings_and_dismissed(pool):
    finding = make_finding(file="a.py", rule_id="B608", tool="security", message="real issue")
    record = CacheWriteRecord(
        owner="o", repo="r", path="a.py", content_hash="hash1", agent="security",
        findings=[finding], tokens_in=100, tokens_out=50, estimated_cost_usd=0.01,
    )

    await write_cache_records(pool, [record])
    hits = await fetch_cache_hits(pool, "o", "r", [("a.py", "hash1", "security")])

    assert ("a.py", "hash1", "security") in hits
    cached = hits[("a.py", "hash1", "security")]
    assert len(cached.findings) == 1
    assert cached.findings[0].rule_id == "B608"
    assert cached.tokens_in == 100
    assert cached.estimated_cost_usd == 0.01


async def test_fetch_cache_hits_is_scoped_to_exact_path_content_hash_agent(pool):
    finding = make_finding(file="a.py", rule_id="B608", tool="security")
    await write_cache_records(pool, [
        CacheWriteRecord(owner="o", repo="r", path="a.py", content_hash="hash1", agent="security", findings=[finding]),
        CacheWriteRecord(owner="o", repo="r", path="a.py", content_hash="hash2", agent="security", findings=[finding]),  # different hash
        CacheWriteRecord(owner="o", repo="r", path="b.py", content_hash="hash1", agent="security", findings=[finding]),  # different path
        CacheWriteRecord(owner="o", repo="r", path="a.py", content_hash="hash1", agent="quality", findings=[finding]),  # different agent
    ])

    hits = await fetch_cache_hits(pool, "o", "r", [("a.py", "hash1", "security")])

    assert set(hits.keys()) == {("a.py", "hash1", "security")}


async def test_write_cache_records_on_conflict_does_nothing(pool):
    original = make_finding(file="a.py", rule_id="B608", tool="security", message="original")
    replacement = make_finding(file="a.py", rule_id="B608", tool="security", message="replacement")

    await write_cache_records(pool, [
        CacheWriteRecord(owner="o", repo="r", path="a.py", content_hash="hash1", agent="security", findings=[original]),
    ])
    await write_cache_records(pool, [
        CacheWriteRecord(owner="o", repo="r", path="a.py", content_hash="hash1", agent="security", findings=[replacement]),
    ])

    hits = await fetch_cache_hits(pool, "o", "r", [("a.py", "hash1", "security")])
    assert hits[("a.py", "hash1", "security")].findings[0].message == "original"
