# Adversarial injection eval

`run_adversarial_eval.py` proves Phase 8's guardrail change actually
holds: a prompt-injection attempt hidden in PR content must be
neutralized before it ever reaches a model, and its presence must not
change what the review pipeline reports. Run it with:

```
python evals/adversarial/run_adversarial_eval.py
```

(needs the repo root on `PYTHONPATH`/an editable install of `codeguard`
— same as `evals/run_eval.py`). Unlike `run_eval.py`, this makes **no**
live Anthropic or Semgrep calls: the Anthropic client is mocked at the
same boundary `tests/pipeline/test_llm_call.py` uses, so it's free and
safe to run anywhere, including CI —
`tests/pipeline/test_adversarial_injection.py` wraps the same functions
as real pytest assertions.

## Vectors

- **`fixtures/{comment,docstring,string_literal}_{clean,injected}.py`**
  — the same injection attempt embedded in three places a PR could hide
  one inside otherwise-unremarkable code. Each `*_injected.py` packs
  three variants: an instruction-style phrase ("ignore previous
  instructions"), a role-play phrase ("act as", "pretend you are"), and
  a base64-obfuscated one.
- **`codeguard_yml/{base,malicious_head}.yml`** — proves `.codeguard.yml`
  is only ever read from the PR's base branch. A PR editing its own
  copy (raising its own budget, disabling the AI-aware agent right
  before submitting the content it would have caught) must have zero
  effect on its own review.
- **`pr_metadata_vectors.py`** — PR title, description, commit message.
  As of Phase 8 none of these ever reach a prompt at all — checked
  structurally (they don't exist as fields on `DiffIngestionResult` or
  `ReviewState`), not by running the pipeline over them, since there's
  no code path to run.

## What this does — and doesn't — prove

`neutralize_injections` is regex/pattern matching. It reliably catches
the instruction-style and role-play phrasing these fixtures use —
including simple delimiter obfuscation (dots/dashes/underscores in
place of spaces) — which is the shape real prompt-injection attempts
documented in the wild actually take. It does **not** catch the
base64-encoded line each `*_injected.py` fixture also carries.
Decoding and semantically interpreting arbitrary obfuscated payloads is
a fundamentally different, much harder problem than pattern matching,
and it's out of scope here. The report marks this explicitly as "a
documented, expected miss" rather than hiding it — three of the three
*recognizable* attempts per fixture are neutralized and counted; the
fourth, obfuscated one is not, on purpose, so the gap stays visible
instead of being quietly asserted away.

The reason an undetected payload is still safe is defense-in-depth, not
detection: everything that reaches a model goes in as clearly delimited
DATA (`nodes.py`'s `_DATA_FRAMING`) inside a system prompt that states
plainly what the agent does and does not do. This harness cannot verify
that a real model actually honors that framing — it never makes a live
call, the same caveat `evals/README.md` already gives for the AI-aware
agent's own fixtures. Treat "review output is identical with and
without the injection" here as proof the *pipeline's own plumbing*
(parsing, caching, severity/confidence clamping) is unaffected by
injected content, not as proof a live model can't be talked into
something with a good enough obfuscated payload.
