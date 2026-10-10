"""Findings from the vendored GitLab rules (JS/TS, Go, Java, C#): what goes
to a model, and what does not.

The verdict contract is the same as Python's: the scanner finds, the
security_generic agent only confirms or dismisses. What this module adds is
the cost and noise control in front of it, all deterministic:

  LOW                         listed as found, no model
  hardcoded-credential rules  the shape classifier decides, no model (nothing
                              about a secret reaches a model): placeholder-like
                              is dropped and counted, anything else is HIGH
  MEDIUM and up               one verdict call per FILE (the verdict contract
                              batches every rule in a file), at most max_files
                              files -- most severe first -- and at most
                              max_findings_per_file per file
  beyond either cap           listed as found, marked unreviewed, and the
                              file named with the reason; never dropped
"""

from __future__ import annotations

from dataclasses import dataclass, field

from codeguard.redact import classify_secret, mask_lines, mask_spans, secret_values
from codeguard.severity import Severity
from codeguard.tools.models import Finding

# Vendored rules whose finding IS "a credential value is hardcoded here".
# (java_password_rule-EmptyDBPassword and csharp_password_rule-
# PasswordComplexity carry no secret value and get a normal verdict.)
GENERIC_CREDENTIAL_RULES = frozenset({
    "java_password_rule-HardcodePassword",
    "java_password_rule-ConstantDBPassword",
})


@dataclass
class Triage:
    to_model: dict[str, list[Finding]] = field(default_factory=dict)
    passthrough: list[Finding] = field(default_factory=list)
    unreviewed: list[Finding] = field(default_factory=list)
    capped_files: list[tuple[str, str]] = field(default_factory=list)
    placeholders: int = 0
    # Lines a credential rule flagged, per file: masked whole before any
    # content goes to the model (content_for_model).
    masked_lines: dict[str, set[int]] = field(default_factory=dict)


def _credential(finding: Finding, content: str) -> tuple[Finding | None, bool]:
    """(finding to report or None, was_placeholder). The value is read from
    the line, classified, and dropped here."""
    lines = content.splitlines()
    line = lines[finding.start_line - 1] if 0 < finding.start_line <= len(lines) else ""
    values = secret_values(line)
    if not values:
        return finding, False
    shapes = [classify_secret(v) for v in values]
    del values
    if all(s.kind == "placeholder-like" for s in shapes):
        return None, True
    body = "; ".join(s.hint()[len("[redacted: "):-1] for s in shapes)
    return finding.model_copy(update={
        "severity": Severity.HIGH,
        "message": f"Hardcoded credential: {body}.",
        "title": "Hardcoded credential",
        "what": f"A value that looks like a real credential is hardcoded here: {body}.",
        "why": "Anyone who can read the code can use it, and it stays in the git history after it is removed.",
        "fix": "Revoke and rotate it, then load it from the environment or a secret manager.",
    }), False


def triage(findings: list[Finding], contents: dict[str, str], *, max_files: int,
           max_findings_per_file: int) -> Triage:
    t = Triage()
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        rule = f.rule_id.rsplit(".", 1)[-1]
        if rule in GENERIC_CREDENTIAL_RULES:
            t.masked_lines.setdefault(f.file, set()).update(range(f.start_line, f.end_line + 1))
            kept, placeholder = _credential(f, contents.get(f.file, ""))
            t.placeholders += placeholder
            if kept is not None:
                t.passthrough.append(kept)
        elif f.severity <= Severity.LOW:
            t.passthrough.append(f)
        else:
            by_file.setdefault(f.file, []).append(f)

    order = sorted(by_file, key=lambda p: (-max(f.severity for f in by_file[p]), -len(by_file[p]), p))
    for rank, path in enumerate(order):
        ranked = sorted(by_file[path], key=lambda f: (-f.severity, f.start_line))
        if rank >= max_files:
            t.unreviewed += [f.model_copy(update={"unreviewed": True}) for f in ranked]
            t.capped_files.append((path, f"not reviewed by AI (cap: {max_files} files)"))
            continue
        t.to_model[path] = ranked[:max_findings_per_file]
        extra = ranked[max_findings_per_file:]
        if extra:
            t.unreviewed += [f.model_copy(update={"unreviewed": True}) for f in extra]
            t.capped_files.append(
                (path, f"{len(extra)} finding(s) not reviewed by AI (cap: {max_findings_per_file} per file)"))
    return t


def content_for_model(path: str, content: str, spans: list[tuple[int, int, int]], t: Triage) -> str:
    """What security_generic may see of one file: the secrets scan's spans
    masked, then every line a credential rule flagged masked whole. One
    function for the audit and the PR path, so the two cannot drift."""
    return mask_lines(mask_spans(content, spans), t.masked_lines.get(path, set()))
