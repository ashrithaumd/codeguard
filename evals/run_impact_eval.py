"""Impact-analysis eval: evals/impact/<case>/{base,head}/ + expected.json.

Each case is a tiny repository at two commits. The patch is the diff
between them; the "repository at the head" is head/. expected.json lists:

  signature    path:line of each caller that must be flagged as no longer
               matching the new signature (deterministic)
  behavior     path:line of each caller the model should flag because it
               relies on changed behaviour; scored by FILE, since the model
               may point at either call in the affected function
  not_flagged  path:line of call sites that must not be flagged at all
  unchecked    path:line of call sites that cannot be checked statically

Two parts:

  * deterministic (default): analyze() and the review_impact node's
    signature findings. No API call, no cost. tests/tooling/
    test_impact_eval.py runs exactly this on every case.
  * --with-model: also makes the node's ONE behaviour call per case, live,
    and reports precision/recall on `behavior` plus tokens and cost. Spends
    Anthropic credit; run it only deliberately.

    docker compose exec -T worker python evals/run_impact_eval.py
    docker compose exec -T worker python evals/run_impact_eval.py --with-model
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "impact"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeguard.config import RepoConfig, get_settings  # noqa: E402
from codeguard.pipeline.impact import ImpactReport, analyze  # noqa: E402
from codeguard.pipeline.impact_review import review_impact  # noqa: E402


def _tree(path: Path) -> dict[str, str]:
    return {p.relative_to(path).as_posix(): p.read_text(encoding="utf-8")
            for p in sorted(path.rglob("*.py"))}


def load_case(case_dir: Path) -> tuple[dict, dict[str, str], dict[str, str], dict[str, str]]:
    base, head = _tree(case_dir / "base"), _tree(case_dir / "head")
    patches = {}
    for path in sorted(set(base) | set(head)):
        if base.get(path) != head.get(path):
            patches[path] = "".join(difflib.unified_diff(
                (base.get(path) or "").splitlines(True), (head.get(path) or "").splitlines(True),
                f"a/{path}", f"b/{path}"))
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    return expected, base, head, patches


def report_for(case_dir: Path) -> tuple[dict, ImpactReport]:
    expected, base, head, patches = load_case(case_dir)
    settings = get_settings()
    report = analyze(head_files=head, base_files={p: base[p] for p in patches if p in base},
                     patches=patches, per_symbol=settings.impact_max_call_sites_per_symbol,
                     per_pr=settings.impact_max_call_sites_per_pr)
    return expected, report


def deterministic_result(case_dir: Path) -> dict:
    expected, report = report_for(case_dir)
    flagged = sorted(f"{s.path}:{s.line}" for s in report.sites if s.mismatch)
    unchecked = sorted(f"{s.path}:{s.line}" for s in report.sites if s.unchecked)
    return {
        "case": case_dir.name,
        "expected_signature": sorted(expected["signature"]), "flagged_signature": flagged,
        "wrongly_flagged": sorted(set(flagged) & set(expected["not_flagged"])),
        "expected_unchecked": sorted(expected["unchecked"]), "unchecked": unchecked,
        "ok": flagged == sorted(expected["signature"]) and set(expected["unchecked"]) <= set(unchecked),
    }


def model_result(case_dir: Path) -> dict:
    expected, report = report_for(case_dir)
    state = {"owner": "eval", "repo": case_dir.name, "pr_number": 1, "head_sha": "0" * 40,
             "repo_config": RepoConfig(), "impact_report": report}
    out = review_impact(state)
    got_files = {c["path"] for c in out.get("impact_callers", []) if c["kind"] == "behavior"}
    want_files = {site.split(":")[0] for site in expected["behavior"]}
    bad_files = {site.split(":")[0] for site in expected["not_flagged"]}
    return {
        "case": case_dir.name, "behavior_expected": sorted(want_files), "behavior_flagged": sorted(got_files),
        "tp": len(got_files & want_files), "fp": len(got_files - want_files), "fn": len(want_files - got_files),
        "flagged_a_not_flagged_file": sorted(got_files & bad_files),
        "notes": out.get("impact_notes", []),
        "tokens_in": out.get("tokens_in", 0), "tokens_out": out.get("tokens_out", 0),
        "cost_usd": out.get("estimated_cost_usd", 0.0),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--with-model", action="store_true", help="also make the live behaviour call (spends credit)")
    args = parser.parse_args(argv)

    cases = sorted(p for p in ROOT.iterdir() if (p / "expected.json").exists())
    failed = False
    print("=== signature (deterministic, no API calls) ===")
    for case in cases:
        r = deterministic_result(case)
        failed |= not r["ok"]
        print(f"  {'OK  ' if r['ok'] else 'FAIL'} {r['case']}: flagged={r['flagged_signature']} "
              f"expected={r['expected_signature']} wrongly_flagged={r['wrongly_flagged']} unchecked={r['unchecked']}")

    if args.with_model:
        print("\n=== behaviour (live model call per case) ===")
        tp = fp = fn = tokens_in = tokens_out = 0
        cost = 0.0
        for case in cases:
            r = model_result(case)
            if r["notes"]:
                print(f"  {r['case']}: CALL FAILED {r['notes']} -- no numbers reported")
                return 2
            tp, fp, fn = tp + r["tp"], fp + r["fp"], fn + r["fn"]
            tokens_in, tokens_out, cost = tokens_in + r["tokens_in"], tokens_out + r["tokens_out"], cost + r["cost_usd"]
            print(f"  {r['case']}: flagged={r['behavior_flagged']} expected={r['behavior_expected']} "
                  f"tokens={r['tokens_in']}/{r['tokens_out']} cost=${r['cost_usd']:.4f}")
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn) if tp + fn else 1.0
        print(f"  behaviour precision={precision:.2f} recall={recall:.2f} (tp={tp} fp={fp} fn={fn})")
        print(f"  total tokens in/out={tokens_in}/{tokens_out} cost=${cost:.4f} "
              f"(${cost / max(1, len(cases)):.4f} per case)")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
