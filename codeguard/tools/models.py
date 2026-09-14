from __future__ import annotations

import hashlib

from pydantic import BaseModel

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
    moment it enters an LLM prompt (Phase 5+) — delimited as data, never
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

    @classmethod
    def create(
        cls, *, file: str, start_line: int, end_line: int, severity: Severity,
        source_tool: str, rule_id: str, message: str,
    ) -> "Finding":
        """fingerprint is derived, not caller-supplied, so two runs
        that produce the same logical finding always dedupe the same
        way — the reuse groundwork Hunk.content_hash laid in Phase 3
        for hunks applies the same idea here, to findings.
        """
        raw = f"{file}:{rule_id}:{start_line}:{message}"
        fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return cls(
            file=file, start_line=start_line, end_line=end_line, severity=severity,
            source_tool=source_tool, rule_id=rule_id, message=message, fingerprint=fingerprint,
        )
