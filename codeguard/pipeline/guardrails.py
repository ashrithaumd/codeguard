"""Phase 7: shared guardrail layer every LLM-calling agent passes
through (see codeguard/pipeline/llm_call.py's call_agent, the one place
this is actually invoked). Ported from v1's guardrails/validators.py,
adapted for a fundamentally different job: v1 validated one human's
interactive submission and could just refuse it outright; v2 reviews a
PR that has to get *some* response regardless of what it contains — a
malicious or malformed PR is exactly the case a reviewer exists to
catch, not silently skip. So the adaptation is:

- Length/token-budget check still hard-skips the LLM call for that one
  chunk (a real cost/latency control, not a content judgment) — falling
  back to whatever deterministic tool findings already exist for it,
  same "never crash the review" discipline as everywhere else in this
  pipeline.
- Prompt-injection and PII pattern hits are FLAGGED, not blocking —
  logged, counted in metrics, and noted in the same delimited data
  block the flagged content already sits in, so the model sees an
  explicit "this content matched a suspicious pattern" marker without
  the review being silently skipped over it.
- Output validation is still a hard check: a degenerate model response
  (empty, or too short to be real structured output) is treated as a
  call failure, same code path as an API exception — the caller falls
  back to raw deterministic findings.
- "Role constraints" isn't a separate check here — it's a prompt-
  authoring discipline applied to every agent's own system prompt (see
  nodes.py): each one states plainly what it does and does not do, the
  same way v1's agents did ("Your only job is X... do NOT repeat Y").
"""

from __future__ import annotations

import logging
import re

import tiktoken

logger = logging.getLogger(__name__)

_tokenizer = tiktoken.get_encoding("cl100k_base")

# A hard per-chunk cap, independent of Settings' PR-wide token budgets
# (effective_budget) — this guards one single piece of content handed
# to one agent call, not the whole PR.
MAX_CHUNK_TOKENS = 20_000

PROMPT_INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"ignore all instructions",
    r"disregard your instructions",
    r"you are now",
    r"pretend you are",
    r"forget your previous",
    r"new instructions",
    r"system prompt",
    r"jailbreak",
]

PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
}


def chunk_exceeds_token_budget(text: str) -> bool:
    return len(_tokenizer.encode(text)) > MAX_CHUNK_TOKENS


def scan_for_flags(text: str) -> list[str]:
    """Returns short machine-readable tags for whatever matched — never
    raises, never blocks. Callers fold these into the delimited data
    block (see llm_call.py) as a caution note, and into a metrics
    counter; they do not change whether the call happens.
    """
    flags: list[str] = []
    lower = text.lower()
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, lower):
            flags.append(f"prompt_injection_pattern:{pattern}")
    for pii_type, pattern in PII_PATTERNS.items():
        if re.search(pattern, text):
            flags.append(f"pii:{pii_type}")
    return flags


def validate_output(raw_text: str) -> bool:
    """A degenerate response (empty, or implausibly short for
    structured JSON output) is treated as a call failure by the caller
    — same fallback path as a raised exception, never a crash.
    """
    return bool(raw_text and raw_text.strip() and len(raw_text.strip()) >= 2)
