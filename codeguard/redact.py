"""Mask credential-shaped text before it is rendered.

This exists because of a specific, documented property of the data:
codeguard/tools/models.py's Finding warns that `message` is
tool-generated but "can echo fragments of the actual scanned code (e.g.
Bandit's own hardcoded-secret message literally includes the matched
string)". Bandit's B105/B106/B107 are *about* hardcoded secrets, so the
finding that says "a secret is hardcoded here" is the one most likely
to contain the secret.

On GitHub that text sits behind the repository's own access control. A
dashboard page for a public repository does not: it is readable with no
login at all, which turns "we found your secret" into "here is your
secret". Redaction happens at render time rather than at write time so
that fixing or widening it applies to rows already stored.

Deliberately over-redacts. A masked value that was harmless costs a
reader one click through to GitHub; an unmasked live key costs a
rotation and an incident. Nothing here is a substitute for rotating a
credential that has been committed — by the time it reaches this
module it is already in the repository's history.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import NamedTuple

MASK = "[redacted]"

# Vendor-prefixed tokens, which are self-identifying and worth matching
# exactly rather than by shape. Ordered longest-prefix-first so
# github_pat_ is not half-consumed by a shorter pattern.
_VENDOR = re.compile(
    r"""(?x)
    \b(?:
        github_pat_[A-Za-z0-9_]{20,}
      | gh[pousr]_[A-Za-z0-9]{16,}
      | sk-ant-[A-Za-z0-9\-_]{16,}
      | sk-[A-Za-z0-9]{20,}
      | sk_(?:live|test)_[A-Za-z0-9]{10,}
      | pk_(?:live|test)_[A-Za-z0-9]{10,}
      | rk_(?:live|test)_[A-Za-z0-9]{10,}
      | AKIA[0-9A-Z]{16}
      | ASIA[0-9A-Z]{16}
      | AIza[0-9A-Za-z\-_]{30,}
      | xox[abposr]-[A-Za-z0-9\-]{10,}
      | glpat-[A-Za-z0-9\-_]{16,}
      | npm_[A-Za-z0-9]{30,}
      | eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}
    )
    """,
)

# A PEM block's body. The header alone is not sensitive and is left
# readable, so the message still says WHAT was found.
_PEM = re.compile(
    r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)",
)

# `password = "..."` and friends: a secret-ish name, an assignment or a
# colon, then a quoted literal. The NAME is kept and only the value is
# masked — "password" is the useful half of the message.
_ASSIGNED = re.compile(
    r"""(?xi)
    (
      \b(?:pass(?:wd|word)?|passphrase|secret|token|api[_\-]?key|apikey
        |auth|credential|private[_\-]?key|access[_\-]?key|client[_\-]?secret
        |connection[_\-]?string|dsn)
      \w*
      \s*(?:=|:=|:|=>)\s*
    )
    # Not a value that is already exactly a mask or a shape hint. Without
    # this, the second redaction pass call_agent makes over every prompt
    # turned the verdict agents' hint back into a bare mask. Anchored on
    # the closing quote, so a hint-looking prefix glued onto a real secret
    # is still a value, and still masked.
    (['"])(?!\[redacted(?::\ [^\]'"\n]{1,80})?\]\2)(?P<value>(?:\\.|(?!\2).){3,})\2
    """,
)

# Credentials embedded in a URL: scheme://user:secret@host.
_URL_CREDS = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s@]{1,200})(@)")

# The same, WITHOUT a colon: scheme://secret@host.
#
# A separate pattern rather than making the colon optional above,
# because the two need different replacements — there the secret is the
# second component and the username survives; here the whole userinfo IS
# the secret and all of it goes.
#
# This is the shape _URL_CREDS missed, and it is the common one:
# `https://<token>@github.com/owner/repo` is how a GitHub PAT is
# normally handed to git. It matters more than the other because git
# itself masks a password-position credential in its error output and
# echoes a username-position one verbatim -- verified against git
# directly, not assumed:
#
#   user:secret@  -> "fatal: Authentication failed for
#                     'https://github.com/owner/repo.git/'"      (masked)
#   secret@       -> "fatal: could not read Password for
#                     'https://ghp_AAAA...@github.com'"          (LEAKED)
#
# Over-redacts a URL whose userinfo is a genuine username, e.g.
# https://alice@example.com. That is the intended trade, per this
# module's docstring: an ordinary https://github.com/owner/repo has no
# `@` at all, so normal URLs are untouched, and a masked username costs
# a reader nothing they cannot recover from the rest of the URL.
_URL_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)([^\s:/@]{1,200})(@)")

# A long unbroken high-entropy run inside quotes. The last net, for a
# token with no recognisable prefix. Length and the mix requirement keep
# it off ordinary prose, file paths and rule ids — all of which contain
# separators this pattern does not allow.
_OPAQUE = re.compile(
    r"""(?x)
    (['"])
    (?P<value>
        (?=[A-Za-z0-9+/=_\-]{32,})     # long enough to be a key
        (?=[^'"]*[A-Za-z])             # and not a pure number
        (?=[^'"]*\d)                   # and not a pure word
        [A-Za-z0-9+/=_\-]{32,}
    )
    \1
    """,
)


# --------------------------------------------------------------------------
# Shape hints, for the verdict agents only
# --------------------------------------------------------------------------
#
# The verdict agents judge findings about hardcoded credentials, and they
# see the file AFTER redaction. A bare `[redacted]` tells them nothing about
# the value behind it, and on codeguard-playground the agent dismissed four
# hardcoded-key hits partly BECAUSE the value read as "the literal
# placeholder string '[redacted]'". A shape hint lets the agent tell
# `...000000000000` from a real key without seeing either: the length, the
# vendor family, and whether the value looks random. None of that is the
# secret. It is never stored or logged -- redact() and redact_source() keep
# the plain MASK unless a caller asks for hints by name.

# Vendor prefixes, stripped before the shape is judged, so that `sk_test_`
# (a real Stripe test-mode credential) is not mistaken for a placeholder
# because it contains "test".
_FAMILIES: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p), name) for p, name in (
        (r"^github_pat_", "github_pat"),
        (r"^gh[pousr]_", "github"),
        (r"^sk-ant-(?:[a-z]+\d+-)?", "sk-ant"),
        (r"^sk-proj-", "sk-proj"),
        (r"^sk_(?:live|test)_", "stripe"),
        (r"^[pr]k_(?:live|test)_", "stripe"),
        (r"^sk-", "sk"),
        (r"^A[KS]IA", "aws"),
        (r"^AIza", "google"),
        (r"^xox[abposr]-", "slack"),
        (r"^glpat-", "gitlab"),
        (r"^npm_", "npm"),
        (r"^eyJ", "jwt"),
    )
)

# Long markers count anywhere: five or more letters do not turn up in a
# random 80-character body by chance. Short ones count only as a whole
# word, so a real key that happens to contain "here" is not a placeholder.
#
# NOT "key", "secret" or "token". They were short markers, and a real key
# that happens to contain "-key-" was then placeholder-like -- dismissable.
# They describe what the value IS, not that it is a stand-in, so they never
# qualify a value on their own; "your-key-here", "example-api-key" or
# "sk-key-000000" are placeholders because of "your", "example" or the
# repeated run, which every such value already carries.
_LONG_MARKERS = re.compile(
    r"(?i)example|placeholder|dummy|sample|changeme|redacted|notreal|not-a-real|insert|replace"
)
_SHORT_MARKERS = re.compile(
    r"(?i)(?<![a-z0-9])(?:fake|test|your|here|xxx+|todo)(?![a-z0-9])"
)
_TEMPLATE_MARKERS = re.compile(r"<[^>]*>|\$\{|\{\{|%\(")


class SecretShape(NamedTuple):
    length: int
    family: str | None
    kind: str  # "high-entropy" | "low-entropy" | "placeholder-like"

    def hint(self) -> str:
        family = f"{self.family}-style " if self.family else ""
        return f"[redacted: {self.length}-char {family}token, {self.kind}]"


# --------------------------------------------------------------------------
# A credential dismissal's reason, written from the shape alone
# --------------------------------------------------------------------------
#
# One place for the wording, so the PR summary and the audit page can group
# by what the dismissal rests on -- the rule and the shape CLASS -- rather
# than by exact text, which differs per value ("42-char ..." vs "43-char
# ..."). Playground's four placeholder keys were three rows for that reason.

_SHAPE_REASON = re.compile(
    r"^Dismissed on the value's shape alone: (?P<shapes>.+)\. Not a usable credential\.$")
_SHAPE_PART = re.compile(r"^(?P<desc>\d+-char (?:\S+-style )?token), (?P<kind>[a-z-]+)$")


def shape_reason(shapes: list[str]) -> str:
    """The reason for one dismissal; `shapes` are hint() bodies, one per
    value on the line ("42-char sk-style token, placeholder-like")."""
    return f"Dismissed on the value's shape alone: {'; '.join(shapes)}. Not a usable credential."


def parse_shape_reason(reason: str) -> tuple[str, list[str]] | None:
    """(shape class, [description per value]) for a reason shape_reason
    wrote whose values all share one class; None for anything else."""
    match = _SHAPE_REASON.match(reason or "")
    if not match:
        return None
    parts = [_SHAPE_PART.match(p.strip()) for p in match.group("shapes").split(";")]
    if not parts or not all(parts) or len({p.group("kind") for p in parts}) != 1:
        return None
    return parts[0].group("kind"), [p.group("desc") for p in parts]


def grouped_shape_reason(kind: str, items: list[tuple[str, str]]) -> str:
    """One reason for several dismissals of one class. `items` are
    (location label, description); each description is listed once with
    every location it applies to, in order of first appearance."""
    where: dict[str, list[str]] = {}
    for label, desc in items:
        labels = where.setdefault(desc, [])
        if label not in labels:
            labels.append(label)
    listed = "; ".join(f"{desc} at {', '.join(labels)}" for desc, labels in where.items())
    return f"Dismissed on the value's shape alone, {kind}: {listed}. Not a usable credential."


def _entropy_bits_per_char(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _longest_run(s: str, step: int) -> int:
    """Longest run of characters each `step` code points after the last:
    0 for repeats (`0000`), 1 for sequences (`1234`, `abcd`)."""
    best = run = 1
    for a, b in zip(s, s[1:]):
        run = run + 1 if ord(b) - ord(a) == step else 1
        best = max(best, run)
    return best


def classify_secret(value: str) -> SecretShape:
    """Describe a credential-shaped value without disclosing it.

    placeholder-like  an obvious stand-in: a marker word ("example",
                      "your-key-here"), a template (`<API_KEY>`), or a
                      repetitive or sequential body (`000000`, `123456`).
    high-entropy      looks random. A credential verdict on one of these is
                      "confirmed", whatever the surrounding comments say.
    low-entropy       neither -- a weak but plausible value, like a
                      human-chosen password. Still a credential.
    """
    family = None
    body = value
    for pattern, name in _FAMILIES:
        m = pattern.match(value)
        if m:
            family, body = name, value[m.end():]
            break

    alnum = re.sub(r"[^A-Za-z0-9]", "", body)
    placeholder = (
        bool(_LONG_MARKERS.search(body))
        or bool(_SHORT_MARKERS.search(body))
        or bool(_TEMPLATE_MARKERS.search(body))
        or (len(alnum) >= 6 and _longest_run(alnum, 0) >= 6)
        or (len(alnum) >= 6 and _longest_run(alnum.lower(), 1) >= 6)
        or (len(alnum) >= 8 and len(set(alnum)) / len(alnum) < 0.3)
    )
    if placeholder:
        kind = "placeholder-like"
    elif len(alnum) >= 12 and _entropy_bits_per_char(alnum) >= 3.0:
        kind = "high-entropy"
    else:
        kind = "low-entropy"
    return SecretShape(length=len(value), family=family, kind=kind)


def secret_values(text: str) -> list[str]:
    """Every value redact() would mask in `text`, in order -- the raw
    values, for classify_secret. Never for display."""
    found: list[str] = []
    for m in _VENDOR.finditer(text):
        found.append(m.group(0))
    remainder = _VENDOR.sub(MASK, text)
    for m in _ASSIGNED.finditer(remainder):
        if m.group("value") != MASK:
            found.append(m.group("value"))
    # The opaque net sees only what the assignment pattern left, exactly
    # as in redact(): scanning `remainder` again reported an assigned key
    # twice, once per pattern.
    remainder = _ASSIGNED.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(2)}", remainder)
    for m in _OPAQUE.finditer(remainder):
        found.append(m.group("value"))
    return found


def redact(text: str, *, hints: bool = False) -> str:
    """Mask anything credential-shaped in `text`.

    Order matters: the vendor patterns run first so a recognised token
    is masked as a whole even when it also sits inside a quoted
    assignment, and the opaque-string net runs last so it only sees what
    nothing more specific has claimed.

    hints=True replaces each value with a SHAPE HINT instead of the bare
    MASK -- see classify_secret. Only the verdict agents' prompts ask for
    it; everything stored, logged or rendered keeps the plain MASK.
    """
    if not text:
        return text

    def mask(value: str) -> str:
        return classify_secret(value).hint() if hints else MASK

    out = _PEM.sub(rf"\1 {MASK} \2", text)
    out = _VENDOR.sub(lambda m: mask(m.group(0)), out)
    out = _URL_CREDS.sub(rf"\1{MASK}\3", out)
    # After _URL_CREDS, never before. _URL_CREDS has already replaced the
    # password with MASK, leaving `scheme://user:[redacted]@host`, and
    # _URL_USERINFO's own character class excludes `:` so it cannot then
    # eat the surviving username. Running it first would collapse
    # `user:secret@` to `[redacted]@` and lose the distinction between a
    # masked password and a masked whole-userinfo.
    out = _URL_USERINFO.sub(rf"\1{MASK}\3", out)
    out = _ASSIGNED.sub(lambda m: f"{m.group(1)}{m.group(2)}{mask(m.group('value'))}{m.group(2)}", out)
    out = _OPAQUE.sub(lambda m: f"{m.group(1)}{mask(m.group('value'))}{m.group(1)}", out)
    return out

# A PEM body line: base64 with no separators. Matched per line so a key
# spanning twenty lines stays twenty lines -- see redact_source.
_PEM_BODY_LINE = re.compile(r"^\s*[A-Za-z0-9+/=]{32,}\s*$")
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


def redact_source(text: str, *, hints: bool = False) -> str:
    """redact(), but guaranteed not to change the number of lines.

    WHY THIS EXISTS SEPARATELY. Findings are LINE-ANCHORED: every one
    carries start_line/end_line, and the dashboard, the fix suggestions and
    the inline PR comments all resolve those against the source. redact()
    collapses a multi-line PEM block onto a single line (_PEM's replacement
    spans the whole match), so redacting source with it would shift every
    line below a hardcoded key and misplace every finding after it. A
    test pins that difference rather than trusting this comment.

    So: each line is redacted INDEPENDENTLY and rejoined. MASK contains no
    newline, so per-line substitution cannot change the line count. PEM
    bodies are masked line by line instead of as a block, which loses the
    "this was one key" shape and keeps the geometry -- the right trade when
    the alternative is every subsequent finding pointing at the wrong line.

    Used for the content sent to the model. redact() remains correct for
    prose -- messages, errors, reports -- where line geometry means nothing.
    """
    if not text:
        return text

    lines = text.splitlines(keepends=False)
    out: list[str] = []
    in_pem = False
    for line in lines:
        if _PEM_BEGIN.search(line):
            in_pem = True
            out.append(redact(line, hints=hints))
            continue
        if _PEM_END.search(line):
            in_pem = False
            out.append(redact(line, hints=hints))
            continue
        if in_pem or _PEM_BODY_LINE.match(line):
            # Keep the indentation so the shape of the file survives; the
            # payload is what matters and it goes.
            leading = line[: len(line) - len(line.lstrip())]
            out.append(f"{leading}{MASK}" if line.strip() else line)
            continue
        out.append(redact(line, hints=hints))

    # splitlines() drops a trailing newline; rebuild it so the output is
    # byte-identical to the input wherever nothing was masked. A source file
    # that gained or lost its final newline would change every downstream
    # hash that reads it.
    joined = "\n".join(out)
    if text.endswith("\n"):
        joined += "\n"
    return joined
