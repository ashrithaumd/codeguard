"""Secrets in every non-Python file type, with Gitleaks.

THE VALUE NEVER LEAVES MEMORY, and nothing about a secret reaches a model.

  1. Gitleaks runs with --redact, so its report never contains a value
     (checked: no generated key appears in any of its 18 output fields).
  2. The runner finds the value in the content it already holds, by
     aligning Gitleaks' redacted Match ("api_key: \\"REDACTED\\"") against
     the line, classifies its SHAPE (redact.classify_secret: length, prefix
     family, kind), optionally computes a KEYED id, and lets it go out of
     scope. It is never logged, stored, returned or rendered.
  3. The shape alone decides, with no model: placeholder-like is not
     reported (only counted); anything else is a HIGH finding. A comment
     saying "this is fake" changes nothing -- whoever wrote the key wrote
     the comment.

What is kept per finding: rule, file, line, the shape hint and the id.

The id is HMAC-SHA256 truncated to 12 hex characters, keyed by
SECRET_HASH_KEY or, failing that, a key derived from the Anthropic key, so
the same secret is recognisable across files without being guessable from
the id: an unkeyed hash of a weak value ("changeme") can simply be reversed
by trying values. With no key at all there is no id.

SCOPE. Python files are excluded (tools/gitleaks.toml): CodeGuard's own
credential rules already cover them, and Python reviews must not change.
Vendored, generated and lockfiles are left out, as are .codeguard.yml
ignored_paths. Docs are scanned on purpose: keys get pasted into READMEs.

PR reviews pass sparse files (sparse_from_patch): only the ADDED lines, at
their head line numbers, so only secrets the PR introduces are reported, at
the right lines, with no extra GitHub call. Audits pass the repository's
files.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from codeguard.config import RepoConfig, get_settings
from codeguard.diff.filters import BUILTIN_IGNORED_PATTERNS
from codeguard.redact import classify_secret
from codeguard.severity import Severity
from codeguard.tools.models import Finding

logger = logging.getLogger(__name__)

TOOL_NAME = "gitleaks"
CONFIG = Path(__file__).with_name("gitleaks.toml")
DEFAULT_TIMEOUT = 60
_DOC_PATTERNS = ("*.md", "*.rst", "*.txt", "*docs/*")
_NOT_SCANNED = tuple(p for p in BUILTIN_IGNORED_PATTERNS if p not in _DOC_PATTERNS)
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
# A token: what a secret is made of, and what the quotes, separators and
# `KEY=` / `key:` around it are not. Base64 padding ("=") is lost from the
# shape's length at worst; a value is never extended into its neighbours.
_TOKEN_CHARS = re.compile(r"[^\s'\"`,;:=<>()\[\]{}]+")
_REDACTED = "REDACTED"


@dataclass
class SecretScan:
    findings: list[Finding] = field(default_factory=list)
    # Placeholder-shaped values Gitleaks matched: not secrets, not reported,
    # only counted (the audit's Skipped section says how many).
    placeholders: int = 0
    unavailable: bool = False


def sparse_from_patch(patch: str) -> str:
    """The file as far as a PR's added lines go: each added line at its head
    line number, every other line empty. Gitleaks then sees exactly what the
    PR introduces, at the lines a review comment would anchor to."""
    lines: dict[int, str] = {}
    line: int | None = None
    for raw in (patch or "").splitlines():
        m = _HUNK.match(raw)
        if m:
            line = int(m.group(1))
            continue
        if line is None or raw.startswith("\\"):
            continue
        if raw.startswith("+"):
            lines[line] = raw[1:]
            line += 1
        elif not raw.startswith("-"):
            line += 1
    if not lines:
        return ""
    return "\n".join(lines.get(i, "") for i in range(1, max(lines) + 1)) + "\n"


def extract_value(line: str, *, match: str, start_col: int, end_col: int) -> str | None:
    """The secret on `line`, located from Gitleaks' REDACTED Match and its
    1-based columns. None when the two cannot be aligned: a finding we cannot
    classify is reported by its rule alone rather than guessed at."""
    if _REDACTED not in match:
        return None
    prefix, suffix = match.split(_REDACTED, 1)
    if not prefix and not suffix:
        # Gitleaks' columns are not exact (measured: off by one in some
        # contexts), so a plain slice can take a quote and lose the
        # token's prefix family. The value is the token run overlapping
        # the reported window instead.
        lo, hi = max(0, start_col - 2), max(start_col, end_col)
        best = max(
            (m for m in _TOKEN_CHARS.finditer(line) if m.start() < hi and m.end() > lo),
            key=lambda m: min(m.end(), hi) - max(m.start(), lo), default=None,
        )
        return best.group(0) if best else None
    if prefix:
        found = line.find(prefix, max(0, start_col - 3))
        if found < 0:
            return None
        start = found + len(prefix)
    else:
        start = start_col - 1
    if suffix:
        end = line.find(suffix, start)
        if end < 0:
            return None
        value = line[start:end]
    else:
        token = _TOKEN_CHARS.match(line, start)
        value = token.group(0) if token else ""
    return value or None


def _id_key() -> bytes | None:
    # The id is optional and the scan is not: settings that cannot load
    # (no ANTHROPIC_API_KEY, found by the smoke test) mean no id, never a
    # failed secrets scan.
    try:
        settings = get_settings()
    except Exception:
        return None
    if settings.secret_hash_key:
        return settings.secret_hash_key.encode()
    if settings.anthropic_api_key:
        return hmac.new(settings.anthropic_api_key.encode(), b"codeguard-secret-id-v1", hashlib.sha256).digest()
    return None


def _secret_id(value: str, key: bytes | None) -> str | None:
    return hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:12] if key else None


def _scannable(path: str, repo_config: RepoConfig) -> bool:
    if path.endswith(".py"):
        return False
    if any(fnmatch.fnmatch(path, p) for p in _NOT_SCANNED):
        return False
    return not any(fnmatch.fnmatch(path, p) for p in repo_config.ignored_paths)


def _finding(path: str, hit: dict, shape_body: str | None, secret_id: str | None) -> Finding:
    # The rule id, not Gitleaks' Description: that is a sentence of prose
    # ("Uncovered a GitHub Personal Access Token, potentially leading to...").
    rule = str(hit.get("RuleID") or "secret")
    shape = f": {shape_body}" if shape_body else ""
    ident = f" (secret id {secret_id})." if secret_id else ""
    return Finding.create(
        file=path, start_line=int(hit["StartLine"]), end_line=int(hit.get("EndLine") or hit["StartLine"]),
        severity=Severity.HIGH, source_tool=TOOL_NAME, rule_id=f"{TOOL_NAME}.{rule}",
        message=f"Hardcoded secret ({rule}){shape}.{ident}",
        title=f"Hardcoded secret: {rule}",
        what=f"A value that looks like a real credential is committed in this file{shape}.",
        why="Anyone who can read the repository can use it, and it stays in the git history after it is removed.",
        fix="Revoke and rotate it, then load it from the environment or a secret manager instead.",
    )


def scan_secrets(files: dict[str, str], repo_config: RepoConfig, timeout: int = DEFAULT_TIMEOUT) -> SecretScan:
    """files: path -> content (full files for an audit, sparse_from_patch()
    output for a PR). Never raises: a Gitleaks failure is `unavailable`."""
    scan = SecretScan()
    targets = {p: c for p, c in files.items() if c and _scannable(p, repo_config)}
    if not targets:
        return scan

    work = Path(tempfile.mkdtemp(prefix="codeguard-gitleaks-"))
    try:
        src = work / "src"
        for rel, content in targets.items():
            dest = src / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
        report = work / "report.json"
        proc = subprocess.run(
            ["gitleaks", "dir", str(src), "--config", str(CONFIG), "--redact", "--no-banner",
             "--report-format", "json", "--report-path", str(report), "--exit-code", "0",
             "--log-level", "error", "--max-target-megabytes", "2"],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0 or not report.exists():
            # stderr is Gitleaks' own diagnostics, never content (--redact).
            logger.warning("gitleaks failed (exit %s): %s", proc.returncode, proc.stderr.strip()[:300])
            scan.unavailable = True
            return scan
        hits = json.loads(report.read_text(encoding="utf-8") or "[]")
    except Exception:
        logger.warning("gitleaks did not run", exc_info=True)
        scan.unavailable = True
        return scan
    finally:
        shutil.rmtree(work, ignore_errors=True)

    key = _id_key()
    for hit in hits:
        path = Path(str(hit.get("File", ""))).as_posix()
        rel = path.split("/src/", 1)[-1] if "/src/" in path else path
        content = targets.get(rel)
        if content is None:
            continue
        lines = content.splitlines()
        start = int(hit.get("StartLine") or 0)
        line = lines[start - 1] if 0 < start <= len(lines) else ""
        value = extract_value(line, match=str(hit.get("Match", "")),
                              start_col=int(hit.get("StartColumn") or 1), end_col=int(hit.get("EndColumn") or 0))
        if value is not None:
            shape = classify_secret(value)
            secret_id = _secret_id(value, key)
            del value  # the only copy outside the caller's own content
            if shape.kind == "placeholder-like":
                scan.placeholders += 1
                continue
            body = shape.hint()[len("[redacted: "):-1]
        else:
            body, secret_id = None, None
        scan.findings.append(_finding(rel, hit, body, secret_id))
    scan.findings.sort(key=lambda f: (f.file, f.start_line))
    return scan
