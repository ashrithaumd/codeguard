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

## Semgrep engine upgrade

Semgrep upgrade blocked past 1.95: later versions drop data-flow traces used by the flow note.

Measured on 2026-10-09: 1.45.0, 1.76.0, 1.85.0, 1.90.0 and 1.95.0 emit `dataflow_trace` for the taint
rules; 1.100.0, 1.120.0, 1.135.0, 1.150.0, 1.165.0 and 1.178.0 do not (the `--dataflow-traces` option is
gone from `--help`). On 1.178.0 the free scanner-only gate (`evals/scanner_snapshot.py`) showed 48 of 49
raw Python findings identical and the injection-through-a-variable finding's source line going from 20
to 0. CodeGuard was then on 1.45.0, which turned out to run five vendored Java rules not at all
(WeakMessageDigest, OgnlInjection, CipherECBMode, CipherIntegrity, WeakTLSProtocol-SSLContext; 463
findings on GitLab's samples vs 524). It moved to 1.95.0: the Python snapshot identical (49/49, source
lines included), the 27 rule tests and the JS/TS LLM rules passing, Java and C# in full. Revisit when
traces return or the flow note can be rebuilt without them.

## Impact analysis for JavaScript/TypeScript (skipped)

Considered with tree-sitter (5–7 days) and skipped for now:

- JavaScript does not fail on a call with the wrong number of arguments: a missing one is `undefined`,
  an extra one is ignored. "No longer matches the signature" is mostly not a runtime error there, which
  is the deterministic half of the Python version.
- TypeScript projects catch real signature breaks with `tsc` in their own CI, better than we could.
- Resolving call sites across files is much harder than in Python: ESM and CommonJS, path aliases from
  tsconfig, barrel `index.ts` files, re-exports, default vs named exports, dynamic `import()`.
- What would remain is the behaviour half (one model call), at a much higher build cost than the Python
  version.

Revisit if users ask for it on JavaScript-heavy repositories, or if a TypeScript-aware resolver (the
TypeScript compiler API in a sidecar) becomes cheap to run.

## Python lockfiles via OSV-Scanner (not built)

Python's dependency check reads only exact `==` pins on lines a PR adds to `requirements.txt` or
`pyproject.toml`, and queries OSV.dev for each (`tools/osv_runner.py`). `poetry.lock`,
`Pipfile.lock` and `uv.lock` are filtered out as lockfiles and never checked, so a vulnerable
version that arrives only through a lockfile (a transitive dependency, or a range in
`pyproject.toml` that resolves to a bad release) is not reported.

OSV-Scanner, which already checks the npm/yarn/pnpm, Go, Maven/Gradle and NuGet lockfiles, reads
all three. Pointing it at Python's lockfiles would work the same way: base vs head on a PR, so
only newly introduced vulnerabilities are reported, and the whole tree on an audit.

**Why not now.** It adds Python findings that today's check never produces, on every PR that
touches a lockfile, and every audit of a repository that has one. That changes Python results, so
it needs its own re-baseline: the Python eval fixtures have no lockfiles, so they would not move,
but real repositories would, and the reliqueue and playground audits would need re-recording.

**Risk.** Duplicates: a pin in `requirements.txt` and the same package in `poetry.lock` would be
reported twice, once by each path. Merge them on (package, version, vulnerability id), or keep
Python's own check for manifests and let OSV-Scanner report only what is in the lockfile alone.

**How to tell it worked.** A PR bumping a package to a known-vulnerable version in `poetry.lock`
alone reports it once; the same PR with an unrelated lockfile change reports nothing; a Python
repository with no lockfile reports exactly what it does today.
