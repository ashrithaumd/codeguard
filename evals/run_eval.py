"""Precision/recall/dismissal-accuracy harness for the AI-aware agent
(codeguard.pipeline.nodes.review_ai_aware). Makes REAL Semgrep
subprocess calls and REAL Anthropic API calls — this is the eval
harness Phase 6/6.1 asked for, not a unit test; tests/pipeline/
test_ai_aware.py covers the node's logic with a mocked client for CI,
with no live calls and no cost.

Usage: python evals/run_eval.py   (run from the repo root; needs
ANTHROPIC_API_KEY set, and Semgrep's native scan engine, which is only
available on Linux — see rules/llm-security.py's own skip note — so
this runs inside the worker container in dev:
    docker exec codeguard-worker-1 python evals/run_eval.py

Two fixture families, evals/ground_truth.json:
- fixture_*.py: planted weaknesses that ARE real — "confirmed" lists
  the rule_id(s) the agent should flag.
- near_miss_*.py: code that syntactically matches a rule but isn't a
  real issue in context — "dismissed" lists the rule_id(s) a
  context-aware reviewer (the agent) should recognize as false
  positives; raw Semgrep has no way to do this, so near-miss fixtures
  are exactly where raw Semgrep's precision should suffer relative to
  the agent's.

Matching is by rule_id set membership per fixture, not by line — the
Phase 6.1 verdict contract is one verdict per distinct rule_id in a
file (see _apply_verdicts in codeguard/pipeline/nodes.py), so rule_id
is the unit both ground truth and the agent's output are expressed in.

See README.md in this directory for what these numbers do and do not
prove.
"""

from __future__ import annotations

import json
from pathlib import Path

from codeguard.pipeline.nodes import review_ai_aware
from codeguard.tools.semgrep_runner import run_semgrep

FIXTURES_DIR = Path(__file__).parent / "fixtures"
GROUND_TRUTH_PATH = Path(__file__).parent / "ground_truth.json"


def _bare_rule_id(rule_id: str) -> str:
    """Semgrep prefixes every rule_id with the loaded ruleset directory
    name — "rules." for rules/llm-security.yaml (confirmed empirically
    during Phase 6, not assumed) — while ground_truth.json is written in
    terms of the rule's own id, directory-name-independent. Strip it
    before comparing so a ruleset directory rename doesn't silently
    break every match.
    """
    prefix = "rules."
    return rule_id[len(prefix):] if rule_id.startswith(prefix) else rule_id


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
    agent_totals = {"tp": 0, "fp": 0, "fn": 0}
    near_miss_dismissal_expected = 0
    near_miss_dismissal_correct = 0
    near_miss_false_confirm: list[tuple[str, str]] = []
    dangerous_false_dismissals: list[tuple[str, str]] = []

    total_tokens_in = total_tokens_out = 0
    total_cost = 0.0
    total_latency = 0.0

    rows = []
    for path in fixture_paths:
        name = path.name
        is_near_miss = name.startswith("near_miss_")
        content = path.read_text(encoding="utf-8")
        gt = ground_truth.get(name, {"confirmed": [], "dismissed": []})
        expected_confirmed = set(gt["confirmed"])
        expected_dismissed = set(gt["dismissed"])

        semgrep_findings = run_semgrep({name: content})
        raw_rule_ids = {_bare_rule_id(f.rule_id) for f in semgrep_findings}
        raw_totals["tp"] += len(raw_rule_ids & expected_confirmed)
        raw_totals["fp"] += len(raw_rule_ids - expected_confirmed)
        raw_totals["fn"] += len(expected_confirmed - raw_rule_ids)

        ai_result = review_ai_aware({
            "owner": "eval", "repo": "eval", "path": name,
            "content": content, "patch": "", "findings": semgrep_findings,
        })
        agent_confirmed_ids = {_bare_rule_id(f.rule_id) for f in ai_result.get("findings", [])}
        agent_dismissed_ids = {_bare_rule_id(d.rule_id) for d in ai_result.get("dismissed_findings", [])}
        agent_totals["tp"] += len(agent_confirmed_ids & expected_confirmed)
        agent_totals["fp"] += len(agent_confirmed_ids - expected_confirmed)
        agent_totals["fn"] += len(expected_confirmed - agent_confirmed_ids)

        if is_near_miss:
            near_miss_dismissal_expected += len(expected_dismissed)
            near_miss_dismissal_correct += len(expected_dismissed & agent_dismissed_ids)
            for rule_id in sorted(expected_dismissed & agent_confirmed_ids):
                near_miss_false_confirm.append((name, rule_id))
        else:
            for rule_id in sorted(expected_confirmed & agent_dismissed_ids):
                dangerous_false_dismissals.append((name, rule_id))

        total_tokens_in += ai_result.get("tokens_in", 0)
        total_tokens_out += ai_result.get("tokens_out", 0)
        total_cost += ai_result.get("estimated_cost_usd", 0.0)
        for lat in ai_result.get("node_latencies", []):
            total_latency += lat["seconds"]

        rows.append((
            name, "near-miss" if is_near_miss else "real",
            len(expected_confirmed), len(expected_dismissed),
            len(raw_rule_ids), len(agent_confirmed_ids), len(agent_dismissed_ids),
        ))

    header = f"{'fixture':<52} {'type':<10} {'exp_conf':>8} {'exp_dism':>8} {'raw#':>5} {'ai_conf#':>8} {'ai_dism#':>8}"
    print(header)
    for name, kind, n_conf, n_dism, n_raw, n_ai_conf, n_ai_dism in rows:
        print(f"{name:<52} {kind:<10} {n_conf:>8} {n_dism:>8} {n_raw:>5} {n_ai_conf:>8} {n_ai_dism:>8}")

    raw_p, raw_r, raw_f1 = _precision_recall_f1(**raw_totals)
    agent_p, agent_r, agent_f1 = _precision_recall_f1(**agent_totals)
    dismissal_recall = near_miss_dismissal_correct / near_miss_dismissal_expected if near_miss_dismissal_expected else 1.0

    print()
    print(f"raw Semgrep:            precision={raw_p:.2f} recall={raw_r:.2f} f1={raw_f1:.2f} "
          f"(tp={raw_totals['tp']} fp={raw_totals['fp']} fn={raw_totals['fn']})")
    print(f"AI-aware agent:         precision={agent_p:.2f} recall={agent_r:.2f} f1={agent_f1:.2f} "
          f"(tp={agent_totals['tp']} fp={agent_totals['fp']} fn={agent_totals['fn']})")
    print(f"dismissal accuracy (near-miss fixtures only): "
          f"{near_miss_dismissal_correct}/{near_miss_dismissal_expected} = {dismissal_recall:.2f} "
          "expected dismissals correctly identified")

    if near_miss_false_confirm:
        print()
        print(f"WARNING: {len(near_miss_false_confirm)} near-miss finding(s) the agent CONFIRMED instead of "
              "dismissing (noisy, not dangerous — a real reviewer would just dismiss it themselves):")
        for name, rule_id in near_miss_false_confirm:
            print(f"  - {name}: {rule_id}")

    if dangerous_false_dismissals:
        print()
        print(f"WARNING: {len(dangerous_false_dismissals)} REAL finding(s) the agent DISMISSED instead of "
              "confirming — a genuine weakness the agent talked itself out of flagging:")
        for name, rule_id in dangerous_false_dismissals:
            print(f"  - {name}: {rule_id}")

    print()
    print(f"tokens_in={total_tokens_in} tokens_out={total_tokens_out} "
          f"estimated_cost_usd={total_cost:.4f} total_latency_s={total_latency:.2f} "
          f"fixtures={len(fixture_paths)}")


if __name__ == "__main__":
    main()
