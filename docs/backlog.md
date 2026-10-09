# Backlog

Ideas recorded for later, not built. Each says what it would change, what it risks, and how to
tell whether it worked.

## Cut the PR review cost back down

**Where it stands.** The 2026-10-08 tour fixes raised the cost per review from $0.196 to $0.262
(+34%) on the 37-fixture eval, with recall up from 0.96 to 1.00 (AI-aware) and 0.92 to 1.00
(security), precision unchanged. Output tokens went from 7,311 to 9,825 per review (+34%), input
from 40,465 to 49,951 (+23%). Almost all of it is two agents:

| Agent | Before | After |
| --- | --- | --- |
| AI-aware (Sonnet) | $0.132 | $0.185 |
| Security (Sonnet) | $0.046 | $0.059 |
| Quality + test (Haiku) | $0.018 | $0.018 |

What they now write that they did not before: a `title`, `what`, `why` and `fix` per verdict, and
a `what` + `fix` per line (`lines`) when a rule occurs on several lines; plus the key-shape hints
on the input side.

**How to measure any of these.** `evals/run_full_harness.py --runs 3`, before and after, on the
same 37 fixtures. A change is worth keeping only if recall stays at 1.00 for AI-aware and security,
dismissal accuracy stays at 1.00, and credential reasons citing anything but the shape stay at 0.
The figures under each idea are guesses until that has run.

1. **Short output for Low verdicts.** Ask for `message` only (no `title`/`what`/`why`/`fix`, no
   `lines`) when the verdict's severity is low. Lows are the bulk of most reports (reliqueue: 20 of
   20), and their detail is what the audit page now folds into one card per rule anyway.
   *Risk:* a Low card with no How to fix. *Guess:* the largest single saving, since output tokens
   are 5× the price of input on Sonnet.

2. **`lines` only when the lines differ.** Ask for per-line `what`/`fix` only when the fix is
   genuinely different per line (the playground's three B608s are; four identical placeholder keys
   are not). Otherwise one `what`/`fix` for the rule. *Risk:* the model under-uses it and the SQL
   case regresses to one generic fix; the per-line-fix assertion on the playground audit catches
   that.

3. **A fixed `why` per rule.** "Why it matters" for a given rule is nearly the same text every time.
   Keep it in the ruleset (one sentence per rule id, reviewed once) and have the model write only
   `what` and `fix`. *Risk:* loses the occasional context-specific why. *Guess:* moderate, and it
   also makes the text consistent.

4. **Haiku for files whose findings are all low-impact rules.** Route the AI-aware verdict call to
   Haiku when every finding in the file is on a rule that is never above Medium (unpinned model
   alias, missing `max_tokens`, missing timeout). *Risk:* dismissal accuracy on the near-miss
   fixtures, which are mostly these rules; this is the one most likely to fail the eval.

5. **Check the prompt cache is actually hit.** The system prompts grew (verdict contract, shape
   rules, the no-line-numbers rule). Confirm from `cache_read_tokens` that each agent's system
   prompt is being read from cache across a PR's calls, and that it is above the minimum cacheable
   length. *Risk:* none; this is measurement first.

6. **Deterministic verdicts where the rule is deterministic.** `llm-unpinned-model-alias` is a
   string check; a verdict call adds little except for dead code (near-miss 02). Confirm it without
   a call unless the line is in an `if False:` block or similar. *Risk:* exactly that near-miss
   class; keep the call for anything not trivially reachable.

Not worth doing: dropping the summary intro (a Haiku call, ~$0.001), or tightening `max_tokens`
(it bounds the worst case, not the typical one).
