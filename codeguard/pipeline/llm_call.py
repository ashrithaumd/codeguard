"""Phase 7: the one place every agent's Anthropic call actually goes
through — guardrail scanning, prompt caching, cost/latency/token
accounting, and metrics, all centralized here instead of duplicated
across review_ai_aware/review_security/review_quality/review_test/
propose_fix/summarize. A node builds its own system prompt and user
content and calls call_agent(); everything past that point is uniform.

Never raises — a failure (API exception, timeout, or output that fails
guardrails.validate_output) comes back as a result with `error` set and
`raw_text=None`, so every caller's existing "fall back to raw
deterministic findings" path also covers a bad LLM response, not just a
network failure.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field

import anthropic
from langsmith.wrappers import wrap_anthropic

from codeguard.pipeline import guardrails
from codeguard.pipeline.metrics import (
    agent_call_duration_seconds,
    agent_call_failures_total,
    agent_cost_usd_total,
    agent_tokens_total,
    guardrail_flags_total,
    injection_attempts_total,
    prompt_cache_hit_total,
)

logger = logging.getLogger(__name__)


def _tracing_enabled() -> bool:
    return os.environ.get("LANGSMITH_TRACING", "").strip().lower() in ("true", "1")


def _build_client(api_key: str) -> tuple[anthropic.Anthropic, bool]:
    """Phase 10: LangSmith tracing, wired at the one real call site
    rather than switching to langchain's ChatAnthropic — this pipeline
    deliberately calls the raw Anthropic SDK directly for precise
    cache-control and cost accounting (see this module's own docstring
    history), and wrap_anthropic() traces a raw client without changing
    any of that.

    Only wraps when LANGSMITH_TRACING is actually on (see .env.example)
    — not just because it's pointless overhead otherwise, but because
    wrap_anthropic() mutates the client object in a way that broke this
    module's own mocked-client unit tests (it doesn't behave as a
    transparent passthrough on a test double the way its "no-op when
    unconfigured" framing might suggest). Checking the env var directly
    ourselves, rather than trusting the wrapped client to no-op
    cleanly, keeps every existing mock-based test working unchanged.
    Wrapping failing at all when tracing IS on never blocks a real
    review — falls back to the unwrapped client, same "observability is
    best-effort, never load-bearing" discipline as the rest of this
    pipeline.
    """
    raw = anthropic.Anthropic(api_key=api_key)
    if not _tracing_enabled():
        return raw, False
    try:
        return wrap_anthropic(raw), True
    except Exception:
        logger.warning("langsmith wrap_anthropic failed, proceeding without tracing", exc_info=True)
        return raw, False

# Published per-million-token pricing by model — a cost *signal* for
# observability (state["estimated_cost_usd"], the per-agent metric),
# never billing-accurate and never gates anything; Settings'
# max_tokens_per_pr_ceiling is the actual hard cost control. Unknown
# model strings fall back to the Sonnet tier's pricing — a conservative
# overestimate rather than a silent zero.
_MODEL_PRICING_PER_MTOK_USD = {
    "claude-sonnet-4-5": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (1.0, 5.0),
}
_DEFAULT_PRICING = (3.0, 15.0)
# Anthropic's published cache-token multipliers on the base input price:
# writing to the cache costs more than a plain input token, reading
# from it costs far less.
_CACHE_WRITE_MULTIPLIER = 1.25
_CACHE_READ_MULTIPLIER = 0.1


@dataclass
class AgentCallResult:
    raw_text: str | None
    tokens_in: int = 0
    tokens_out: int = 0
    cache_write_tokens: int = 0
    cache_read_tokens: int = 0
    estimated_cost_usd: float = 0.0
    latency_s: float = 0.0
    error: str | None = None
    guardrail_flags: list[str] = field(default_factory=list)
    # Phase 8: how many prompt-injection matches were neutralized out of
    # user_content before the prompt was ever built — 0 in the common
    # case. The raw matched text itself is never carried on this result
    # (see guardrails.InjectionAttempt); fingerprints only.
    injection_attempt_fingerprints: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and self.raw_text is not None


def _cost_usd(model: str, tokens_in: int, tokens_out: int, cache_write: int, cache_read: int) -> float:
    input_price, output_price = _MODEL_PRICING_PER_MTOK_USD.get(model, _DEFAULT_PRICING)
    return (
        tokens_in / 1_000_000 * input_price
        + cache_write / 1_000_000 * input_price * _CACHE_WRITE_MULTIPLIER
        + cache_read / 1_000_000 * input_price * _CACHE_READ_MULTIPLIER
        + tokens_out / 1_000_000 * output_price
    )


def call_agent(
    *,
    agent: str,
    api_key: str,
    system_prompt: str,
    repo_context: str,
    user_content: str,
    model: str,
    max_tokens: int,
    timeout: float,
) -> AgentCallResult:
    """system_prompt and repo_context are each their own prompt-cache
    breakpoint (see the `system=` list below): system_prompt is
    identical across every call this agent ever makes; repo_context
    (e.g. "reviewing a PR in owner/repo") is identical across every
    file/hunk in one PR for one agent. user_content — the actual file/
    hunk/findings data — is never cached, since it's different on every
    call by definition. Both breakpoints are what let a 5-file PR's
    five calls to the same agent, and a same-repo PR reviewed again
    later, hit Anthropic's own cache for everything except the part
    that actually changed.

    Phase 8: guardrails.neutralize_injections runs against user_content
    BEFORE anything else — every matched span is stripped out and
    replaced with a marker, logged with its fingerprint, and counted in
    injection_attempts_total. The neutralized text (never the original)
    is what actually goes into the API request; the review continues on
    whatever's left rather than the call being skipped. PII pattern hits
    (guardrails.scan_for_pii) are still flagged, not blocked, against
    that same neutralized text. A chunk over guardrails.MAX_CHUNK_TOKENS
    (measured on the neutralized text, since that's what's actually
    sent) skips the call entirely and returns an error result, the same
    shape as any other failure.
    """
    user_content, injection_attempts = guardrails.neutralize_injections(user_content)
    for attempt in injection_attempts:
        injection_attempts_total.labels(agent=agent, pattern=attempt.pattern).inc()
        logger.warning(
            "blocked prompt-injection attempt in %s input: pattern=%r fingerprint=%s",
            agent, attempt.pattern, attempt.fingerprint,
        )
    injection_fingerprints = [a.fingerprint for a in injection_attempts]

    flags = guardrails.scan_for_pii(user_content)
    if flags:
        for f in flags:
            guardrail_flags_total.labels(agent=agent, flag_type=f.split(":", 1)[0]).inc()
        logger.warning("guardrail flag(s) on %s input: %s", agent, flags)

    if guardrails.chunk_exceeds_token_budget(user_content):
        agent_call_failures_total.labels(agent=agent).inc()
        return AgentCallResult(
            raw_text=None, error="input exceeds MAX_CHUNK_TOKENS",
            guardrail_flags=flags, injection_attempt_fingerprints=injection_fingerprints,
        )

    client, traced = _build_client(api_key)
    create_kwargs = dict(
        model=model,
        system=[
            {"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": repo_context, "cache_control": {"type": "ephemeral"}},
        ],
        messages=[{"role": "user", "content": user_content}],
        max_tokens=max_tokens,
        timeout=timeout,
    )
    if traced:
        # Only added once wrap_anthropic actually succeeded — the raw
        # (unwrapped) client raises on this kwarg, it doesn't ignore it.
        create_kwargs["langsmith_extra"] = {"tags": [agent], "metadata": {"repo_context": repo_context}}

    start = time.perf_counter()
    try:
        response = client.messages.create(**create_kwargs)
    except Exception as exc:
        elapsed = time.perf_counter() - start
        agent_call_duration_seconds.labels(agent=agent).observe(elapsed)
        agent_call_failures_total.labels(agent=agent).inc()
        logger.exception("%s call failed", agent)
        return AgentCallResult(
            raw_text=None, latency_s=elapsed, error=str(exc),
            guardrail_flags=flags, injection_attempt_fingerprints=injection_fingerprints,
        )
    elapsed = time.perf_counter() - start
    agent_call_duration_seconds.labels(agent=agent).observe(elapsed)

    raw_text = response.content[0].text if response.content else ""
    if not guardrails.validate_output(raw_text):
        agent_call_failures_total.labels(agent=agent).inc()
        return AgentCallResult(
            raw_text=None, latency_s=elapsed, error="output failed validation (empty/degenerate)",
            guardrail_flags=flags, injection_attempt_fingerprints=injection_fingerprints,
        )

    usage = response.usage
    tokens_in = usage.input_tokens
    tokens_out = usage.output_tokens
    cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
    cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
    cost = _cost_usd(model, tokens_in, tokens_out, cache_write, cache_read)

    agent_tokens_total.labels(agent=agent, direction="in").inc(tokens_in)
    agent_tokens_total.labels(agent=agent, direction="out").inc(tokens_out)
    agent_tokens_total.labels(agent=agent, direction="cache_write").inc(cache_write)
    agent_tokens_total.labels(agent=agent, direction="cache_read").inc(cache_read)
    agent_cost_usd_total.labels(agent=agent).inc(cost)
    prompt_cache_hit_total.labels(agent=agent, outcome="hit" if cache_read > 0 else "miss").inc()

    return AgentCallResult(
        raw_text=raw_text, tokens_in=tokens_in, tokens_out=tokens_out,
        cache_write_tokens=cache_write, cache_read_tokens=cache_read,
        estimated_cost_usd=cost, latency_s=elapsed, guardrail_flags=flags,
        injection_attempt_fingerprints=injection_fingerprints,
    )
