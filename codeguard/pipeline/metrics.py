"""Pipeline-level metrics — per-agent latency/tokens/cost, plus the two
distinct notions of "cache" this pipeline has: Anthropic's own prompt
cache (does a single call reuse cached system/repo-context tokens) and
this pipeline's own hunk-level result cache (does a call happen at all,
see codeguard/pipeline/hunk_cache.py). Both are measurable in cache hit
rate and cost, but are genuinely different things, so they're separate
metrics rather than one overloaded counter.
"""

from prometheus_client import Counter, Histogram

agent_call_duration_seconds = Histogram(
    "codeguard_agent_call_duration_seconds",
    "Wall time for one LLM agent call (excludes a hunk-cache hit, which never calls the API).",
    ["agent"],
)
agent_tokens_total = Counter(
    "codeguard_agent_tokens_total",
    "Tokens actually billed for, by agent and direction.",
    ["agent", "direction"],  # direction: in | out | cache_write | cache_read
)
agent_cost_usd_total = Counter(
    "codeguard_agent_cost_usd_total",
    "Estimated cost in USD, by agent — a signal, not a billing-accurate figure (see llm_call.py).",
    ["agent"],
)
agent_call_failures_total = Counter(
    "codeguard_agent_call_failures_total",
    "Agent calls that raised, timed out, or failed output validation.",
    ["agent"],
)
guardrail_flags_total = Counter(
    "codeguard_guardrail_flags_total",
    "PII pattern hits flagged before a call (never blocks it) — see injection_attempts_total "
    "for the separate, blocking, prompt-injection path.",
    ["agent", "flag_type"],
)
injection_attempts_total = Counter(
    "codeguard_injection_attempts_total",
    "Prompt-injection pattern matches neutralized before the prompt was built. Each "
    "increment is one blocked attempt that never reached the model's instruction context.",
    ["agent", "pattern"],
)
prompt_cache_hit_total = Counter(
    "codeguard_prompt_cache_hit_total",
    "Anthropic-side prompt cache outcome per call, by agent and hit/miss.",
    ["agent", "outcome"],  # outcome: hit | miss
)
hunk_cache_total = Counter(
    "codeguard_hunk_cache_total",
    "This pipeline's own content-hash result cache: whether a call was skipped entirely.",
    ["agent", "outcome"],  # outcome: hit | miss
)
verdict_flip_total = Counter(
    "codeguard_verdict_flip_total",
    "A 'confirmed' verdict whose own rationale reads like a dismissal (e.g. 'no "
    "action needed') and was flipped to dismissed instead of surfaced as actionable — see "
    "nodes.py's _apply_verdicts. Labeled by agent only; rule_id cardinality is unbounded.",
    ["agent"],
)
fix_suggestions_dropped_total = Counter(
    "codeguard_fix_suggestions_dropped_total",
    "Fix suggestions withheld at generation time. reason='original_mismatch' means the fix agent's "
    "echo of the code it was replacing did not match the finding's own lines in the file — i.e. the "
    "suggestion was about different code than the line it would have replaced, which is one click "
    "from corrupting the file. Should be rare; a sustained non-zero rate means the agents upstream "
    "are mislocating findings. reason='model_located_finding' means the finding's line came from a "
    "generative agent rather than a scanner, so no suggestion is anchored to it at all — expected to "
    "be zero in practice, since route_after_fanin already filters those before the fix agent is "
    "called; a non-zero rate means something is routing generative findings into propose_fix. "
    "reason='parse_break' means the file parses today and would not after the replacement. "
    "reason='duplicates_following_lines' means the replacement ended with lines already sitting "
    "below the range it replaces, which a suggestion block duplicates rather than changes. "
    "reason='range_outside_diff' means the replaced range ran past the diff GitHub computed.",
    ["reason"],
)
