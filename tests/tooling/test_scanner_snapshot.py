"""The free gate: the scanners alone, on every Python fixture, must produce
exactly the committed snapshot (evals/scanner_snapshot_python.json).

Taken with Semgrep 1.45.0 and identical on 1.95.0, Bandit 1.7.9, Ruff 0.6.9. Any change to a
scanner, a rule, or the shared scan path that alters a single raw Python
finding -- a rule, a line, a severity, a taint source line -- fails here,
before any paid eval could be needed to notice it. No model, no network.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_PATH = Path(__file__).resolve().parents[2] / "evals" / "scanner_snapshot.py"
_spec = importlib.util.spec_from_file_location("scanner_snapshot", _PATH)
snap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(snap)

BASELINE = _PATH.parent / "scanner_snapshot_python.json"


def test_the_diff_reports_both_directions():
    a = [{"file": "f", "rule": "r", "start": 1}]
    b = [{"file": "f", "rule": "r", "start": 2}]
    gone, new = snap.diff(a, b)
    assert gone == a and new == b
    assert snap.diff(a, a) == ([], [])


def test_the_python_fixtures_produce_exactly_the_baseline():
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert len(baseline) == 49
    gone, new = snap.diff(baseline, snap.snapshot())
    assert (gone, new) == ([], []), f"changed raw findings: -{gone} +{new}"


def test_the_taint_finding_keeps_its_source_line():
    """The property the 1.178 upgrade lost (20 -> 0)."""
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    [row] = [r for r in baseline if r["file"].endswith("regress_01_injection_through_variable.py")
             and r["rule"].endswith("llm-prompt-injection-concatenation")]
    assert (row["source_line"], row["start"]) == (20, 26)
