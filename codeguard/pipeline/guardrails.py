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
- Phase 8: prompt-injection hits are BLOCKED, not flagged — a detected
  attempt never reaches the model's instruction context at all. See
  neutralize_injections: every matched span is stripped out of the text
  before call_agent builds the prompt, the attempt is logged with a
  fingerprint, and codeguard_injection_attempts_total is incremented.
  The review still continues on whatever content is left — this is a
  content-hygiene step, not a call-blocking one; only a chunk that fails
  the token-budget check below skips the call entirely.
- PII pattern hits (scan_for_pii) are still FLAGGED, not blocking —
  logged, counted in metrics, and noted in the same delimited data
  block the flagged content already sits in, so the model sees an
  explicit "this content matched a suspicious pattern" marker without
  the review being silently skipped over it. Unlike injection text, a
  PII pattern hit doesn't itself threaten to hijack the model's
  behavior, so flagging (surfacing it to a human) is the right response,
  not stripping it out of a security finding a reviewer needs to see.
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

import hashlib
import logging
import re

import tiktoken
from pydantic import BaseModel

logger = logging.getLogger(__name__)

_tokenizer = tiktoken.get_encoding("cl100k_base")

# A hard per-chunk cap, independent of Settings' PR-wide token budgets
# (effective_budget) — this guards one single piece of content handed
# to one agent call, not the whole PR.
MAX_CHUNK_TOKENS = 20_000

# Word/phrase separator tolerant of simple delimiter-substitution
# obfuscation (dots, dashes, underscores, extra whitespace) in place of
# a plain space — e.g. "ignore.previous.instructions" or
# "ignore_previous_instructions" match the same as "ignore previous
# instructions". Not a defense against heavier obfuscation (base64,
# unicode homoglyphs, zero-width characters) — see
# evals/adversarial/README.md for what this detector does and doesn't
# catch; the DATA-framing + role-constrained system prompts (nodes.py)
# are the defense-in-depth for whatever a regex can't recognize.
_SEP = r"[\s\-_.]+"
PROMPT_INJECTION_PATTERNS = [
    rf"ignore{_SEP}(?:all|any|previous|prior){_SEP}instructions?",
    rf"disregard{_SEP}(?:all|any|your|previous|prior){_SEP}instructions?",
    rf"you{_SEP}are{_SEP}now",
    rf"pretend{_SEP}(?:you{_SEP}are|to{_SEP}be)",
    rf"forget{_SEP}(?:all|your|any){_SEP}(?:previous|prior)?{_SEP}?instructions?",
    rf"new{_SEP}instructions?",
    rf"system{_SEP}prompt",
    r"jailbreak",
    rf"act{_SEP}as{_SEP}(?:a|an|if)",
    rf"reveal{_SEP}(?:your|the){_SEP}(?:system{_SEP}prompt|instructions)",
]

PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
}

# What a neutralized span is replaced with — visible in the prompt as
# an explicit marker (rather than silently vanishing) so a reviewer
# reading logs/output can tell content was removed here, without any of
# the original text surviving into the model's context.
INJECTION_REDACTION_MARKER = "[content removed: matched a prompt-injection pattern]"


class InjectionAttempt(BaseModel):
    """One neutralized injection match — never carries the raw matched
    text itself (that's exactly the content being kept out of logs/
    metrics, not just out of the model's prompt); `fingerprint` lets an
    operator dedupe/correlate repeated attempts without reconstructing
    the original payload.
    """
    pattern: str
    fingerprint: str


def _injection_fingerprint(pattern: str, matched_text: str) -> str:
    raw = f"{pattern}:{matched_text.lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def chunk_exceeds_token_budget(text: str) -> bool:
    return len(_tokenizer.encode(text)) > MAX_CHUNK_TOKENS


def neutralize_injections(text: str) -> tuple[str, list[InjectionAttempt]]:
    """The Phase 8 block-not-flag gate: every span matching
    PROMPT_INJECTION_PATTERNS is replaced with INJECTION_REDACTION_MARKER
    before this text is allowed anywhere near a prompt — the caller
    (call_agent) uses the returned text, never the original, to build
    the actual API request. Returns the neutralized text plus one
    InjectionAttempt per match (a chunk with three matches, whether the
    same pattern three times or three different ones, yields three
    attempts — each independently logged and counted).
    """
    attempts: list[InjectionAttempt] = []

    def _redact(match: re.Match, pattern: str) -> str:
        attempts.append(InjectionAttempt(pattern=pattern, fingerprint=_injection_fingerprint(pattern, match.group(0))))
        return INJECTION_REDACTION_MARKER

    result = text
    for pattern in PROMPT_INJECTION_PATTERNS:
        result = re.sub(pattern, lambda m, p=pattern: _redact(m, p), result, flags=re.IGNORECASE)
    return result, attempts


def scan_for_pii(text: str) -> list[str]:
    """PII pattern hits only — flag-not-block (see module docstring).
    Split out from the old combined scan_for_flags so call_agent can gate
    injection (block) and PII (flag) through genuinely different code
    paths rather than one list mixing two different response policies.
    """
    flags: list[str] = []
    for pii_type, pattern in PII_PATTERNS.items():
        if re.search(pattern, text):
            flags.append(f"pii:{pii_type}")
    return flags


def scan_for_flags(text: str) -> list[str]:
    """Detection-only combined view (injection patterns + PII), kept for
    callers that just want to know what *would* match, not enforce
    anything — e.g. tests asserting the patterns themselves work. Never
    called by call_agent directly: it uses neutralize_injections
    (block) and scan_for_pii (flag) instead, since those are the two
    genuinely different response policies Phase 8 requires.
    """
    flags: list[str] = []
    lower = text.lower()
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, lower):
            flags.append(f"prompt_injection_pattern:{pattern}")
    flags.extend(scan_for_pii(text))
    return flags


def validate_output(raw_text: str) -> bool:
    """A degenerate response (empty, or implausibly short for
    structured JSON output) is treated as a call failure by the caller
    — same fallback path as a raised exception, never a crash.
    """
    return bool(raw_text and raw_text.strip() and len(raw_text.strip()) >= 2)
