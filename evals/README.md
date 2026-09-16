# AI-aware agent eval harness

`run_eval.py` measures `codeguard.pipeline.nodes.review_ai_aware` against
the fixtures in `fixtures/`, using `ground_truth.json` as the answer key.
Run it with:

```
docker exec codeguard-worker-1 python evals/run_eval.py
```

(Semgrep's native engine isn't available on Windows, and this makes real
Anthropic API calls — see `run_eval.py`'s own docstring.)

## Two fixture families

- **`fixture_*.py`** — planted weaknesses that are genuinely real. Ground
  truth's `"confirmed"` list is the rule_id(s) the agent should flag.
- **`near_miss_*.py`** — code that syntactically matches a rule but isn't
  actually a problem in context (a value set via `**kwargs`, dead code, a
  wrapper that already enforces the missing thing, a trusted constant, a
  test-only dummy credential, a client-level default). Ground truth's
  `"dismissed"` list is the rule_id(s) a context-aware reviewer should
  recognize as false positives. Raw Semgrep has no way to do this — it has
  no concept of dismissal — so these fixtures are where raw Semgrep's
  precision is *expected* to suffer relative to the agent's.

## What the report shows

Three numbers, not one: raw-Semgrep precision/recall/F1, the AI-aware
agent's precision/recall/F1 (both computed the same way, against the same
`"confirmed"` ground truth, across every fixture including near-misses),
and a separate dismissal-accuracy number scoped to just the near-miss
fixtures — what fraction of the findings that *should* have been
dismissed actually were.

It also separately flags two different failure shapes, because they are
not the same severity of problem:

- **Near-miss false confirm** — the agent flagged a near-miss instead of
  dismissing it. Noisy, not dangerous: a human reviewer would just
  dismiss it themselves, the same as they'd dismiss the raw Semgrep
  finding today.
- **Dangerous false dismissal** — the agent dismissed something from a
  *real* fixture instead of confirming it. This is the actual risk the
  whole verdict contract introduces that raw Semgrep-only reporting
  didn't have: a real weakness talked away with a plausible-sounding
  reason. `_ensure_full_coverage`'s backfill only catches a rule_id the
  model never addresses at all — it does **not** catch a wrong verdict on
  one it did address. `Settings.ai_aware_dismissals_enabled=False` is the
  fail-safe lever for this specific risk: set it and no dismissal is ever
  trusted, full stop, regardless of how the agent seems to be performing
  on these fixtures.

## What this does — and doesn't — prove

**A perfect or near-perfect score here is not independent evidence that
the agent is accurate.** These fixtures, the rules they were built to
test, and the system prompt were all written by the same person, working
from the same mental model of what should and shouldn't fire. A high
score mostly shows internal consistency — the implementation does what
its own author expected it to do — not that it generalizes to code
someone else wrote, wording the model wasn't tuned against, or an
adversarial PR deliberately trying to talk it into a bad dismissal.

Real evidence would come from a held-out set built independently of the
rules/prompt — e.g. sampled from real historical PRs with a known
outcome, or fixtures written by someone who didn't write the agent. That
doesn't exist yet. Until it does, treat these numbers as a regression
gate (did a change make things worse against what we already agreed
should happen), not as a claim about real-world accuracy.
