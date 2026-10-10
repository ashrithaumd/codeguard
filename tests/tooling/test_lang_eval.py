"""The free half of evals/run_lang_eval.py: on every multi-language fixture
the scanners raise exactly the expected rules, and every one of those
findings would reach the model (none is passthrough or capped), so the paid
half measures the verdict and nothing else. No model, no network."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_PATH = Path(__file__).resolve().parents[2] / "evals" / "run_lang_eval.py"
_spec = importlib.util.spec_from_file_location("run_lang_eval", _PATH)
lang_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lang_eval)


def test_every_fixture_fires_exactly_its_rules_and_only_raised_ones_reach_the_model():
    det = lang_eval.deterministic_result()
    bad = [r for r in det["rows"] if not r["ok"]]
    assert bad == []


def test_every_language_has_a_planted_bug_and_a_near_miss():
    expected, _ = lang_eval.load()
    for lang in ("javascript", "typescript", "go", "java"):
        verdicts = {v["verdict"] for p, v in expected.items() if p.startswith(lang + "/")}
        assert {"confirmed", "dismissed"} <= verdicts <= {"confirmed", "dismissed", "not_raised"}, lang


def test_not_raised_means_no_rule_and_raised_means_at_least_one():
    expected, _ = lang_eval.load()
    for path, want in expected.items():
        assert (want["rules"] == []) == (want["verdict"] == "not_raised"), path
