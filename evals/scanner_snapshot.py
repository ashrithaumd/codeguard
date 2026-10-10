"""The scanners alone, no model: a deterministic snapshot of raw findings.

Runs Semgrep (our rules), Bandit and Ruff over every Python fixture and
prints the findings in a canonical, sorted JSON form. Two snapshots taken
with different engine versions, or before and after a change to shared
code, must be IDENTICAL -- that is the free gate run before the paid eval
(evals/run_full_harness.py) at every commit that touches the scan path.

Compared on what the review acts on: file, tool, rule, severity, lines,
and the taint source line. Not on message text, which is the rule's own
wording and is checked by the rule tests instead.

    docker compose exec -T worker python evals/scanner_snapshot.py > /tmp/after.json
    python evals/scanner_snapshot.py --diff before.json after.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))

FIXTURE_DIRS = ("fixtures", "fixtures_security", "fixtures_quality_test", "adversarial/fixtures", "dogfood")


def snapshot() -> list[dict]:
    from codeguard.tools.run_all import RUNNERS

    rows: list[dict] = []
    for d in FIXTURE_DIRS:
        base = ROOT / d
        files = {p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8")
                 for p in sorted(base.rglob("*.py"))}
        if not files:
            continue
        for runner in RUNNERS:
            for f in runner(files):
                rows.append({
                    "file": f.file, "tool": f.source_tool, "rule": f.rule_id, "severity": f.severity.name,
                    "start": f.start_line, "end": f.end_line, "source_line": getattr(f, "source_line", 0) or 0,
                })
    return sorted(rows, key=lambda r: (r["file"], r["tool"], r["rule"], r["start"], r["end"], r["source_line"]))


def diff(before: list[dict], after: list[dict]) -> tuple[list[dict], list[dict]]:
    key = lambda r: json.dumps(r, sort_keys=True)  # noqa: E731
    b, a = {key(r) for r in before}, {key(r) for r in after}
    return [json.loads(k) for k in sorted(b - a)], [json.loads(k) for k in sorted(a - b)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--diff", nargs=2, metavar=("BEFORE", "AFTER"))
    args = parser.parse_args(argv)
    if args.diff:
        before, after = (json.loads(Path(p).read_text(encoding="utf-8")) for p in args.diff)
        gone, new = diff(before, after)
        print(f"before={len(before)} after={len(after)} only_before={len(gone)} only_after={len(new)}")
        for r in gone:
            print("  - ", r)
        for r in new:
            print("  + ", r)
        return 1 if gone or new else 0
    json.dump(snapshot(), sys.stdout, indent=1)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
