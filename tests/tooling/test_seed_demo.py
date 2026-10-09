"""The demo seed data must never show numbers the real writer cannot produce.

The previous seed script hand-entered every count, and the dashboard
dutifully showed the result: "9 dismissed" over an empty list, a banner
saying 48 files were skipped over a list of 5. Those were reported as bugs
in the review page; they were bugs in the sample data. The real writer
(pipeline/reviews.py) derives each count from the list it stores, and so
does scripts/seed_demo.py now -- these tests hold it to that.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "seed_demo.py"


def _load():
    spec = importlib.util.spec_from_file_location("seed_demo", _PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # must not touch a database on import
    return mod


seed = _load()
ROWS = [seed.build_review_row(t) for t in seed.review_templates()]


@pytest.mark.parametrize("row", ROWS, ids=lambda r: f"pr{r['pr']}-{r['action']}")
def test_every_count_matches_its_list(row):
    assert row["dismissed_count"] == len(row["dismissed_json"])
    assert row["files_seen"] - row["files_reviewed"] == len({f["path"] for f in row["filtered"]})
    assert row["findings_total"] == len(row["findings"])
    assert sum(row["buckets"]) == row["findings_total"]
    assert row["fix_suggestion_count"] == len(row["fix_suggestions"])
    assert row["inline_count"] <= row["findings_total"]
    assert row["budget_exceeded"] == any("budget" in f["reason"] for f in row["filtered"])


@pytest.mark.parametrize("row", ROWS, ids=lambda r: f"pr{r['pr']}-{r['action']}")
def test_dismissed_entries_have_the_dismissed_shape(row):
    for d in row["dismissed_json"]:
        assert set(d) == {"file", "start_line", "rule_id", "reason"}


@pytest.mark.parametrize("row", ROWS, ids=lambda r: f"pr{r['pr']}-{r['action']}")
def test_every_row_is_labelled_sample(row):
    assert row["summary"].startswith("SAMPLE DATA")
    assert row["title"].startswith("[SAMPLE]")
    assert all(f["message"].startswith("SAMPLE.") for f in row["findings"])
    assert all(d["reason"].startswith("SAMPLE.") for d in row["dismissed_json"])
    assert row["pr"] >= 9001


def test_the_sample_audit_is_labelled_and_structured():
    data = seed.sample_audit_report_json("ashrithaumd", "demo")
    md = seed.sample_audit_markdown("ashrithaumd", "demo")
    assert "SAMPLE DATA" in md
    assert data["version"] == seed.REPORT_DATA_VERSION
    assert data["summary"]["total"] == len(data["findings"])
    counts = data["summary"]["counts"]
    assert sum(counts.values()) == len(data["findings"])
    assert data["summary"]["dismissed"] == len(data["dismissed"])
    assert all(f["what"].startswith("SAMPLE.") for f in data["findings"])


def test_importing_the_script_does_not_run_it():
    assert hasattr(seed, "main")


def test_the_report_version_matches_the_package():
    from codeguard.report_format import REPORT_DATA_VERSION
    assert seed.REPORT_DATA_VERSION == REPORT_DATA_VERSION
