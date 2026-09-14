"""Phase 7 pipeline-level metrics — per-agent latency/tokens/cost, plus
the two distinct notions of "cache" this pipeline has: Anthropic's own
prompt cache (does a single call reuse cached system/repo-context
tokens) and this pipeline's own hunk-level result cache (does a call
happen at all, see codeguard/pipeline/hunk_cache.py). Both matter for
the Phase 7 done-when criterion ("measurable in cache hit rate and
cost") but are genuinely different things, so they're separate metrics
rather than one overloaded counter.
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
    "Prompt-injection/PII pattern hits flagged before a call (never blocks it).",
    ["agent", "flag_type"],
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
