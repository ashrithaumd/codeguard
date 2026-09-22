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

import re

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
    (['"])(?P<value>(?:\\.|(?!\2).){3,})\2
    """,
)

# Credentials embedded in a URL: scheme://user:secret@host.
_URL_CREDS = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+:)([^\s@]{1,200})(@)")

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


def redact(text: str) -> str:
    """Mask anything credential-shaped in `text`.

    Order matters: the vendor patterns run first so a recognised token
    is masked as a whole even when it also sits inside a quoted
    assignment, and the opaque-string net runs last so it only sees what
    nothing more specific has claimed.
    """
    if not text:
        return text

    out = _PEM.sub(rf"\1 {MASK} \2", text)
    out = _VENDOR.sub(MASK, out)
    out = _URL_CREDS.sub(rf"\1{MASK}\3", out)
    out = _ASSIGNED.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}{m.group(2)}", out)
    out = _OPAQUE.sub(lambda m: f"{m.group(1)}{MASK}{m.group(1)}", out)
    return out
