"""The impact eval's deterministic half, on every case in evals/impact/.

No API call: the signature check is a tool, so it is held to the answer
key exactly -- the caller the PR breaks without touching it is flagged at
its line, and the near-misses (already passing the new argument, a
**kwargs forwarder, a different function with the same name) are not.
The behaviour half needs the model and runs only via
`evals/run_impact_eval.py --with-model`.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "evals" / "run_impact_eval.py"
_spec = importlib.util.spec_from_file_location("run_impact_eval", _PATH)
harness = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(harness)

CASES = sorted(p for p in harness.ROOT.iterdir() if (p / "expected.json").exists())


def test_there_is_a_signature_case_and_a_behaviour_case():
    names = [c.name for c in CASES]
    assert "impact_01_signature_break" in names and "impact_02_behavior" in names


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.name)
def test_the_signature_check_matches_the_answer_key(case):
    r = harness.deterministic_result(case)
    assert r["flagged_signature"] == r["expected_signature"]
    assert r["wrongly_flagged"] == []
    assert set(r["expected_unchecked"]) <= set(r["unchecked"])


def test_the_unchanged_caller_is_flagged_with_the_reason():
    _, report = harness.report_for(harness.ROOT / "impact_01_signature_break")
    [site] = [s for s in report.sites if s.mismatch]
    assert (site.path, site.line, site.in_diff) == ("api/checkout.py", 8, False)
    assert site.mismatch == "missing required keyword argument 'idempotency_key'"


def test_the_behaviour_case_has_no_signature_finding_but_reaches_the_model_with_its_callers():
    _, report = harness.report_for(harness.ROOT / "impact_02_behavior")
    [sym] = report.symbols
    assert sym.qualname == "get_setting" and sym.body_changed and not sym.signature_changed
    assert {s.path for s in report.sites} == {"app/boot.py", "app/report.py"}
    assert not any(s.mismatch for s in report.sites)


def test_the_runner_exits_zero_without_the_model():
    assert harness.main([]) == 0
