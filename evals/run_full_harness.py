"""Phase 9: the full live eval harness — AI-aware, Security, Quality,
and Test agents, each against its own fixture set, through the REAL
pipeline (live Anthropic calls; AI-aware/Security also make a real
Semgrep/Bandit subprocess call). Real cost, real cost reporting; no
mocking anywhere in this file. Run from inside the worker container
(Semgrep's native engine is Linux-only):

    docker exec codeguard-worker-1 python evals/run_full_harness.py --runs 3 --json evals/full_harness_results.json

AI-aware reuses evals/fixtures/ + ground_truth.json (Phase 6/6.1, already
established). Security is the same rule_id-set-membership methodology
applied to evals/fixtures_security/ (Bandit, not Semgrep). Quality/Test
have no rule_id to match against — they're the ungrounded agents (see
Phase 8) — so evals/fixtures_quality_test/ground_truth.json is a
per-fixture binary "should this file get at least one real flag"
expectation instead; see that directory's own fixtures for why each one
is scoped to make that binary call unambiguous.

Every run is independent (no caching reuse across runs — this script
talks to the node functions directly, never through hunk_cache) so
running this 3x gives real call-to-call variance, not the same cached
answer three times.
"""

from __future__ import annotations

import argparse
import json
import statistics
from dataclasses import asdict, dataclass, field
from pathlib import Path

from codeguard.pipeline.nodes import review_ai_aware, review_quality, review_security, review_test
from codeguard.tools.bandit_runner import run_bandit
from codeguard.tools.semgrep_runner import run_semgrep

FIXTURES_AI_AWARE = Path(__file__).parent / "fixtures"
# Phase 6's ground_truth.json lives one level up from fixtures/, not
# inside it (see evals/run_eval.py) — the newer fixtures_security/ and
# fixtures_quality_test/ keep their own ground_truth.json alongside
# their fixtures instead, which is why _run_verdict_contract_eval takes
# an explicit ground_truth_path rather than assuming fixtures_dir/"ground_truth.json".
AI_AWARE_GROUND_TRUTH = Path(__file__).parent / "ground_truth.json"
FIXTURES_SECURITY = Path(__file__).parent / "fixtures_security"
FIXTURES_QUALITY_TEST = Path(__file__).parent / "fixtures_quality_test"


def _bare_rule_id(rule_id: str) -> str:
    prefix = "rules."
    return rule_id[len(prefix):] if rule_id.startswith(prefix) else rule_id


def _precision_recall_f1(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


@dataclass
class AgentEvalResult:
    agent: str
    precision: float
    recall: float
    f1: float
    dismissal_accuracy: float | None
    tp: int
    fp: int
    fn: int
    tokens_in: int
    tokens_out: int
    cost_usd: float
    latency_s: float
    n_fixtures: int


def _run_verdict_contract_eval(agent: str, fixtures_dir: Path, ground_truth_path: Path, run_tool, review_fn) -> AgentEvalResult:
    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    fixture_paths = sorted(fixtures_dir.glob("*.py"))

    totals = {"tp": 0, "fp": 0, "fn": 0}
    dismissal_expected = 0
    dismissal_correct = 0
    tokens_in = tokens_out = 0
    cost = 0.0
    latency = 0.0

    for path in fixture_paths:
        name = path.name
        content = path.read_text(encoding="utf-8")
        gt = ground_truth.get(name, {"confirmed": [], "dismissed": []})
        expected_confirmed = set(gt["confirmed"])
        expected_dismissed = set(gt["dismissed"])

        tool_findings = run_tool({name: content})
        result = review_fn({
            "owner": "eval", "repo": "eval", "path": name,
            "content": content, "patch": "", "findings": tool_findings, "hunk_cache_hits": {},
        })
        confirmed_ids = {_bare_rule_id(f.rule_id) for f in result.get("findings", [])}
        dismissed_ids = {_bare_rule_id(d.rule_id) for d in result.get("dismissed_findings", [])}

        totals["tp"] += len(confirmed_ids & expected_confirmed)
        totals["fp"] += len(confirmed_ids - expected_confirmed)
        totals["fn"] += len(expected_confirmed - confirmed_ids)
        dismissal_expected += len(expected_dismissed)
        dismissal_correct += len(expected_dismissed & dismissed_ids)

        tokens_in += result.get("tokens_in", 0)
        tokens_out += result.get("tokens_out", 0)
        cost += result.get("estimated_cost_usd", 0.0)
        for lat in result.get("node_latencies", []):
            latency += lat["seconds"]

    precision, recall, f1 = _precision_recall_f1(**totals)
    dismissal_accuracy = dismissal_correct / dismissal_expected if dismissal_expected else None

    return AgentEvalResult(
        agent=agent, precision=precision, recall=recall, f1=f1, dismissal_accuracy=dismissal_accuracy,
        tp=totals["tp"], fp=totals["fp"], fn=totals["fn"],
        tokens_in=tokens_in, tokens_out=tokens_out, cost_usd=cost, latency_s=latency,
        n_fixtures=len(fixture_paths),
    )


def run_ai_aware_eval() -> AgentEvalResult:
    return _run_verdict_contract_eval("ai_aware", FIXTURES_AI_AWARE, AI_AWARE_GROUND_TRUTH, run_semgrep, review_ai_aware)


def run_security_eval() -> AgentEvalResult:
    return _run_verdict_contract_eval("security", FIXTURES_SECURITY, FIXTURES_SECURITY / "ground_truth.json", run_bandit, review_security)


@dataclass
class BinaryEvalResult:
    agent: str
    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int
    tn: int
    tokens_in: int
    tokens_out: int
    cost_usd: float
    latency_s: float
    n_fixtures: int
    per_fixture: dict = field(default_factory=dict)


def run_quality_and_test_eval() -> tuple[BinaryEvalResult, BinaryEvalResult]:
    ground_truth = json.loads((FIXTURES_QUALITY_TEST / "ground_truth.json").read_text(encoding="utf-8"))
    fixture_paths = sorted(FIXTURES_QUALITY_TEST.glob("*.py"))

    counts = {
        "quality": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "tokens_in": 0, "tokens_out": 0, "cost": 0.0, "latency": 0.0},
        "test": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "tokens_in": 0, "tokens_out": 0, "cost": 0.0, "latency": 0.0},
    }
    per_fixture = {"quality": {}, "test": {}}

    for path in fixture_paths:
        name = path.name
        content = path.read_text(encoding="utf-8")
        gt = ground_truth[name]
        end_line = len(content.splitlines())

        for agent, review_fn, expect_key in [
            ("quality", review_quality, "expect_quality_flag"),
            ("test", review_test, "expect_test_flag"),
        ]:
            result = review_fn({
                "owner": "eval", "repo": "eval", "path": name, "content": content,
                "content_hash": name, "start_line": 1, "end_line": end_line, "hunk_cache_hits": {},
            })
            flagged = len(result.get("findings", [])) > 0
            expected = gt[expect_key]

            if flagged and expected:
                counts[agent]["tp"] += 1
            elif flagged and not expected:
                counts[agent]["fp"] += 1
            elif not flagged and expected:
                counts[agent]["fn"] += 1
            else:
                counts[agent]["tn"] += 1

            counts[agent]["tokens_in"] += result.get("tokens_in", 0)
            counts[agent]["tokens_out"] += result.get("tokens_out", 0)
            counts[agent]["cost"] += result.get("estimated_cost_usd", 0.0)
            for lat in result.get("node_latencies", []):
                counts[agent]["latency"] += lat["seconds"]
            per_fixture[agent][name] = {"flagged": flagged, "expected": expected}

    results = []
    for agent in ("quality", "test"):
        c = counts[agent]
        precision, recall, f1 = _precision_recall_f1(c["tp"], c["fp"], c["fn"])
        results.append(BinaryEvalResult(
            agent=agent, precision=precision, recall=recall, f1=f1,
            tp=c["tp"], fp=c["fp"], fn=c["fn"], tn=c["tn"],
            tokens_in=c["tokens_in"], tokens_out=c["tokens_out"], cost_usd=c["cost"], latency_s=c["latency"],
            n_fixtures=len(fixture_paths), per_fixture=per_fixture[agent],
        ))
    return tuple(results)


def run_once() -> dict:
    ai_aware = run_ai_aware_eval()
    security = run_security_eval()
    quality, test = run_quality_and_test_eval()
    per_pr_tokens = ai_aware.tokens_in + ai_aware.tokens_out + security.tokens_in + security.tokens_out + quality.tokens_in + quality.tokens_out + test.tokens_in + test.tokens_out
    per_pr_cost = ai_aware.cost_usd + security.cost_usd + quality.cost_usd + test.cost_usd
    per_pr_latency = ai_aware.latency_s + security.latency_s + quality.latency_s + test.latency_s
    return {
        "ai_aware": asdict(ai_aware), "security": asdict(security),
        "quality": asdict(quality), "test": asdict(test),
        "per_pr_tokens": per_pr_tokens, "per_pr_cost_usd": per_pr_cost, "per_pr_latency_s": per_pr_latency,
    }


def _print_run(i: int, run: dict) -> None:
    print(f"--- run {i + 1} ---")
    for agent in ("ai_aware", "security", "quality", "test"):
        r = run[agent]
        dismissal = f", dismissal_acc={r['dismissal_accuracy']:.2f}" if r.get("dismissal_accuracy") is not None else ""
        print(
            f"  {agent:<10} precision={r['precision']:.2f} recall={r['recall']:.2f} f1={r['f1']:.2f} "
            f"(tp={r['tp']} fp={r['fp']} fn={r['fn']}){dismissal} "
            f"tokens_in={r['tokens_in']} tokens_out={r['tokens_out']} cost_usd={r['cost_usd']:.4f} latency_s={r['latency_s']:.2f}"
        )
    print(f"  per-PR-equivalent: tokens={run['per_pr_tokens']} cost_usd={run['per_pr_cost_usd']:.4f} latency_s={run['per_pr_latency_s']:.2f}")


def _variance_report(runs: list[dict]) -> None:
    print()
    print("=== variance across runs ===")
    for agent in ("ai_aware", "security", "quality", "test"):
        for metric in ("precision", "recall", "f1", "cost_usd", "latency_s"):
            values = [r[agent][metric] for r in runs]
            print(f"  {agent}.{metric}: {[round(v, 4) for v in values]} (stdev={statistics.pstdev(values):.4f})")
    total_costs = [r["per_pr_cost_usd"] for r in runs]
    print(f"  per_pr_cost_usd: {[round(v, 4) for v in total_costs]} (stdev={statistics.pstdev(total_costs):.4f})")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--json", type=str, default=None)
    args = parser.parse_args()

    runs = []
    for i in range(args.runs):
        run = run_once()
        _print_run(i, run)
        runs.append(run)

    _variance_report(runs)

    if args.json:
        Path(args.json).write_text(json.dumps(runs, indent=2), encoding="utf-8")
        print(f"\nwrote raw results to {args.json}")


if __name__ == "__main__":
    main()
