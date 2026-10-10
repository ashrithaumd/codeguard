"""Multi-language eval: evals/fixtures_lang/ + expected.json.

Each fixture is one JavaScript, TypeScript, Go or Java file: a planted bug
the model must confirm, or a near miss the same rule fires on that the model
must dismiss. expected.json gives, per file, the exact rule ids the scanners
must raise and the verdict expected for them.

Two parts:

  * deterministic (default): the vendored rules plus rules_lang/ over every
    fixture, compared with `rules`, and the triage that decides what would
    reach the model. No API call, no cost. tests/tooling/test_lang_eval.py
    runs exactly this.
  * --with-model: also makes the security_generic verdict call per file,
    live, and reports precision/recall on `verdict` plus tokens and cost.
    Spends Anthropic credit; run it only deliberately.

    docker compose exec -T worker python evals/run_lang_eval.py
    docker compose exec -T worker python evals/run_lang_eval.py --with-model
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "fixtures_lang"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeguard.pipeline.generic_review import triage  # noqa: E402
from codeguard.tools.semgrep_runner import run_vendor_rules  # noqa: E402


def load() -> tuple[dict, dict[str, str]]:
    expected = json.loads((ROOT / "expected.json").read_text(encoding="utf-8"))
    files = {p: (ROOT / p).read_text(encoding="utf-8") for p in expected}
    return expected, files


def deterministic_result() -> dict:
    expected, files = load()
    findings = run_vendor_rules(files)
    fired: dict[str, list[str]] = {p: [] for p in files}
    for f in findings:
        fired.setdefault(f.file, []).append(f.rule_id)
    t = triage(findings, files, max_files=len(files), max_findings_per_file=30)
    rows = []
    for path, want in expected.items():
        got = sorted(set(fired.get(path, [])))
        rows.append({"file": path, "expected_rules": sorted(want["rules"]), "fired": got,
                     "to_model": path in t.to_model, "ok": got == sorted(want["rules"]) and path in t.to_model})
    return {"rows": rows, "findings": findings, "triage": t, "files": files, "expected": expected,
            "ok": all(r["ok"] for r in rows)}


def model_result(det: dict) -> dict:
    from codeguard.pipeline.nodes import review_security_generic

    expected, files, t = det["expected"], det["files"], det["triage"]
    tp = fp = fn = tn = 0
    tokens_in = tokens_out = 0
    cost = 0.0
    rows = []
    for path, findings in t.to_model.items():
        result = review_security_generic({"owner": "eval", "repo": "fixtures_lang", "path": path,
                                          "content": files[path], "patch": "", "findings": findings,
                                          "hunk_cache_hits": {}})
        confirmed = bool(result.get("findings"))
        want = expected[path]["verdict"] == "confirmed"
        tp += confirmed and want
        fp += confirmed and not want
        fn += (not confirmed) and want
        tn += (not confirmed) and not want
        tokens_in += result.get("tokens_in", 0)
        tokens_out += result.get("tokens_out", 0)
        cost += result.get("estimated_cost_usd", 0.0)
        rows.append({"file": path, "expected": expected[path]["verdict"],
                     "got": "confirmed" if confirmed else "dismissed",
                     "failures": [f.reason for f in result.get("verdict_call_failures", [])]})
    return {"rows": rows, "precision": tp / (tp + fp) if tp + fp else 1.0,
            "recall": tp / (tp + fn) if tp + fn else 1.0,
            "tokens_in": tokens_in, "tokens_out": tokens_out, "cost_usd": round(cost, 4)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--with-model", action="store_true", help="also make the live verdict calls (spends credit)")
    args = parser.parse_args(argv)

    det = deterministic_result()
    for r in det["rows"]:
        print(f"{'ok  ' if r['ok'] else 'FAIL'} {r['file']}: fired {r['fired']} (expected {r['expected_rules']})")
    out = {"deterministic_ok": det["ok"]}
    if args.with_model:
        model = model_result(det)
        for r in model["rows"]:
            mark = "ok  " if r["expected"] == r["got"] else "MISS"
            print(f"{mark} {r['file']}: {r['got']} (expected {r['expected']}){' ' + str(r['failures']) if r['failures'] else ''}")
        out.update({k: v for k, v in model.items() if k != "rows"})
    print(json.dumps(out, indent=2))
    return 0 if det["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
