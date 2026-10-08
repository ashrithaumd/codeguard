from __future__ import annotations

import hashlib

from pydantic import BaseModel

from codeguard.redact import redact
from codeguard.severity import Severity


class Finding(BaseModel):
    """Common schema every deterministic tool runner normalizes into —
    Semgrep, Bandit, and Ruff each have their own output shape; nothing
    downstream of this module should need to know which tool produced
    a given finding beyond `source_tool`.

    SECURITY: `message` is tool-generated but can echo fragments of the
    actual scanned code (e.g. Bandit's own hardcoded-secret message
    literally includes the matched string). It is derived from PR
    content, not written by us, and must be treated as untrusted the
    moment it enters an LLM prompt — delimited as data, never
    concatenated in as an instruction — the same discipline raw hunk
    content already requires.
    """
    file: str
    start_line: int
    end_line: int
    severity: Severity
    source_tool: str
    rule_id: str
    message: str
    fingerprint: str
    # Only ever < 1.0 for a finding an ungrounded agent
    # (Quality/Test — see nodes.py) generated from scratch and
    # self-rated; every deterministic-tool and verdict-contract finding
    # (Bandit/Semgrep/Ruff passthrough, Security, AI-aware) keeps the
    # default, since there's no model self-rating involved. Not part of
    # the fingerprint — it's a noise-budget signal, not identity.
    confidence: float = 1.0
    # Optional structure a verdict agent MAY return alongside `message`
    # (see nodes._VERDICT_CONTRACT): a short title, what is wrong on THIS
    # line, why it matters, and how to fix it. Empty when the agent gave
    # none, and always for tool passthrough -- every reader falls back to
    # `message`. Not part of the fingerprint, for the same reason as
    # confidence: presentation, not identity. Defaulted, so every
    # findings_json row and hunk_findings entry written before these
    # existed still loads.
    title: str = ""
    what: str = ""
    why: str = ""
    fix: str = ""
    # Every rule that reported this same bug at this location, when
    # findings from two tools were merged into one (see
    # pipeline/merge.py). Empty for an unmerged finding, whose only
    # source is rule_id.
    sources: list[str] = []
    # For a taint finding: the line where the tainted value was BUILT,
    # when the tool traced it from somewhere other than the line it reports
    # (the sink). 0 when there is no such line. Not part of the
    # fingerprint, and the tool's message is never rewritten to include it
    # -- the fingerprint hashes the message, and suppressions key on that.
    source_line: int = 0
    # True when the verdict call that should have judged this finding
    # FAILED and it is the scanner's raw finding, reported unreviewed
    # (nodes._run_verdict_agent's fallback). Every surface that shows a
    # finding says so: a fallback that looks exactly like a reviewed
    # result is how an exhausted API credit went unnoticed mid-eval.
    unreviewed: bool = False

    @classmethod
    def create(
        cls, *, file: str, start_line: int, end_line: int, severity: Severity,
        source_tool: str, rule_id: str, message: str, confidence: float = 1.0,
        title: str = "", what: str = "", why: str = "", fix: str = "",
    ) -> "Finding":
        """fingerprint is derived, not caller-supplied, so two runs
        that produce the same logical finding always dedupe the same
        way — the same content-hash-keyed reuse idea Hunk.content_hash
        applies to hunks, applied here to findings instead.
        """
        # HASH THE ORIGINAL, STORE THE REDACTED. The order is the whole
        # point and it is not interchangeable.
        #
        # The fingerprint is derived from the message, so redacting before
        # hashing would change the fingerprint of every finding whose
        # message quotes a secret -- and fingerprints are the key that
        # finding_feedback and posted_comments store suppressions and
        # posted comments against. A user who marked a finding as a false
        # positive would silently stop being listened to, for exactly the
        # findings most worth suppressing. This function has broken
        # suggestions and the feedback loop once before by re-deriving a
        # fingerprint; it does not get to do it twice.
        #
        # So identity comes from the unredacted text and only the STORED
        # message is masked. The hash of a string containing a secret is
        # not a disclosure: it is one-way, truncated to 16 hex characters,
        # and it is what has always been stored.
        raw = f"{file}:{rule_id}:{start_line}:{message}"
        fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

        # UPSTREAM of the database, the logs, the API and the prompt.
        # Redaction used to happen only at render time, which left the
        # secret in reviews.findings_json, in the worker's logs, in the
        # JSON poll response, and in the text sent to Anthropic. The
        # render-time filter stays as a second layer for rows written
        # before this.
        return cls(
            file=file, start_line=start_line, end_line=end_line, severity=severity,
            source_tool=source_tool, rule_id=rule_id, message=redact(message),
            fingerprint=fingerprint, confidence=confidence,
            title=redact(title), what=redact(what), why=redact(why), fix=redact(fix),
        )
