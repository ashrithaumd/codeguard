"""Precision/recall harness for the AI-aware agent (codeguard.pipeline.
nodes.review_ai_aware). Makes REAL Semgrep subprocess calls and REAL
Anthropic API calls — this is the eval harness Phase 6 asked for, not a
unit test; tests/pipeline/test_ai_aware.py covers the node's logic with
a mocked client for CI, with no live calls and no cost.

Usage: python evals/run_eval.py   (run from the repo root; needs
ANTHROPIC_API_KEY set, and Semgrep's native scan engine, which is only
available on Linux — see rules/llm-security.py's own skip note — so
this runs inside the worker container in dev:
    docker exec codeguard-worker-1 python evals/run_eval.py

Matching a predicted finding to a ground-truth weakness is by (file,
line-within-tolerance) — not exact rule_id string equality. The
AI-aware agent's whole job is to interpret/merge/re-rank Semgrep's raw
output; a renamed or merged rule_id is expected, sometimes correct,
behavior, not a matching failure. TOLERANCE_LINES bounds "close enough
to be the same weakness."
"""

from __future__ import annotations

import json
from pathlib import Path

from codeguard.pipeline.nodes import review_ai_aware
from codeguard.tools.semgrep_runner import run_semgrep

FIXTURES_DIR = Path(__file__).parent / "fixtures"
GROUND_TRUTH_PATH = Path(__file__).parent / "ground_truth.json"
TOLERANCE_LINES = 3


def _match(ground_truth: list[dict], predicted_lines: list[int]) -> tuple[int, int, int]:
    """Greedy line-tolerance matching. Returns (tp, fp, fn)."""
    unmatched_gt = list(range(len(ground_truth)))
    tp = 0
    fp = 0
    for line in predicted_lines:
        hit = next((i for i in unmatched_gt if abs(line - ground_truth[i]["line"]) <= TOLERANCE_LINES), None)
        if hit is not None:
            unmatched_gt.remove(hit)
            tp += 1
        else:
            fp += 1
    fn = len(unmatched_gt)
    return tp, fp, fn


def _precision_recall_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def main() -> None:
    ground_truth = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    fixture_paths = sorted(FIXTURES_DIR.glob("*.py"))
    if not fixture_paths:
        raise SystemExit(f"no fixtures found under {FIXTURES_DIR}")

    raw_totals = {"tp": 0, "fp": 0, "fn": 0}
    ai_totals = {"tp": 0, "fp": 0, "fn": 0}
    total_tokens_in = total_tokens_out = 0
    total_cost = 0.0
    total_latency = 0.0

    rows = []
    for path in fixture_paths:
        name = path.name
        content = path.read_text(encoding="utf-8")
        gt = ground_truth.get(name, [])

        semgrep_findings = run_semgrep({name: content})
        raw_lines = [f.start_line for f in semgrep_findings]
        raw_tp, raw_fp, raw_fn = _match(gt, raw_lines)
        raw_totals["tp"] += raw_tp
        raw_totals["fp"] += raw_fp
        raw_totals["fn"] += raw_fn

        ai_result = review_ai_aware({
            "owner": "eval", "repo": "eval", "path": name,
            "content": content, "patch": "", "findings": semgrep_findings,
        })
        ai_findings = ai_result.get("findings", [])
        ai_lines = [f.start_line for f in ai_findings]
        ai_tp, ai_fp, ai_fn = _match(gt, ai_lines)
        ai_totals["tp"] += ai_tp
        ai_totals["fp"] += ai_fp
        ai_totals["fn"] += ai_fn

        total_tokens_in += ai_result.get("tokens_in", 0)
        total_tokens_out += ai_result.get("tokens_out", 0)
        total_cost += ai_result.get("estimated_cost_usd", 0.0)
        for lat in ai_result.get("node_latencies", []):
            total_latency += lat["seconds"]

        rows.append((name, len(gt), len(semgrep_findings), raw_tp, raw_fp, raw_fn, len(ai_findings), ai_tp, ai_fp, ai_fn))

    print(f"{'fixture':<52} {'gt':>3} {'raw#':>5} {'raw_tp':>6} {'raw_fp':>6} {'raw_fn':>6}   {'ai#':>4} {'ai_tp':>5} {'ai_fp':>5} {'ai_fn':>5}")
    for name, n_gt, n_raw, raw_tp, raw_fp, raw_fn, n_ai, ai_tp, ai_fp, ai_fn in rows:
        print(f"{name:<52} {n_gt:>3} {n_raw:>5} {raw_tp:>6} {raw_fp:>6} {raw_fn:>6}   {n_ai:>4} {ai_tp:>5} {ai_fp:>5} {ai_fn:>5}")

    raw_p, raw_r, raw_f1 = _precision_recall_f1(**raw_totals)
    ai_p, ai_r, ai_f1 = _precision_recall_f1(**ai_totals)

    print()
    print(f"raw Semgrep (pre-AI):   precision={raw_p:.2f} recall={raw_r:.2f} f1={raw_f1:.2f} "
          f"(tp={raw_totals['tp']} fp={raw_totals['fp']} fn={raw_totals['fn']})")
    print(f"AI-aware agent:         precision={ai_p:.2f} recall={ai_r:.2f} f1={ai_f1:.2f} "
          f"(tp={ai_totals['tp']} fp={ai_totals['fp']} fn={ai_totals['fn']})")
    print()
    print(f"tokens_in={total_tokens_in} tokens_out={total_tokens_out} "
          f"estimated_cost_usd={total_cost:.4f} total_latency_s={total_latency:.2f} "
          f"fixtures={len(fixture_paths)}")


if __name__ == "__main__":
    main()
