"""Secrets must be redacted BEFORE they leave us, not at render time.

THE VULNERABILITY THIS REPRODUCES
---------------------------------
Redaction was render-time only: `templates.env.filters["redact"]` applied
in review.html, repo.html, pr.html and audit.html. So a secret found in a
repository was stored unredacted in reviews.findings_json and
audits.report_markdown, written unredacted to the worker's logs, returned
unredacted by the JSON poll endpoint, and -- the one that leaves our
infrastructure entirely -- SENT TO ANTHROPIC in the prompt.

Two paths carry it, and the second is the bigger one:

  1. Finding.message. Bandit's B105/B106/B107 messages quote the matched
     string, so "a secret is hardcoded here" contains the secret.
  2. THE SOURCE CODE ITSELF. The prompt includes file content, so
     `API_KEY = "sk-live-..."` reaches the model whether or not any
     scanner noticed it. Redacting messages alone leaves this wide open.

LINE NUMBERS MUST NOT MOVE. Findings are line-anchored, so redaction of
source content has to be a same-line substitution. redact() as it stands
collapses a multi-line PEM block onto one line, which would shift every
line number below it and misplace every finding after the key.

AND FINGERPRINTS MUST NOT CHANGE. Finding.create derives the fingerprint
from f"{file}:{rule_id}:{start_line}:{message}" -- the MESSAGE IS IN THE
HASH. Redacting the message before hashing would change the fingerprint of
every finding that contained a secret, silently orphaning the suppressions
stored against it in finding_feedback and posted_comments. This function
has broken suggestions and the feedback loop once before by re-deriving
fingerprints, so the hash is taken from the original text and only the
STORED message is redacted.
"""

from __future__ import annotations

import hashlib

from codeguard.redact import MASK, redact, redact_source
from codeguard.severity import Severity
from codeguard.tools.models import Finding

SECRET = "sk-live-" + "9f3c" * 8
GH_TOKEN = "ghp_" + "d" * 36


# --- amendment 4: fingerprint stability --------------------------------


def _fingerprint_of(message: str) -> str:
    """The derivation as models.py performs it, spelled out so this test
    fails loudly if the formula changes rather than silently agreeing."""
    raw = f"app.py:B105:7:{message}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _finding(message: str) -> Finding:
    return Finding.create(
        file="app.py", start_line=7, end_line=7, severity=Severity.HIGH,
        source_tool="bandit", rule_id="B105", message=message,
    )


def test_the_fingerprint_is_unchanged_by_redaction():
    """The regression amendment 4 asks for.

    The fingerprint must be what it was before redaction existed: derived
    from the ORIGINAL message. Anything else invalidates every stored
    suppression for findings that mention a secret.
    """
    original = f'Possible hardcoded password: "{SECRET}"'
    finding = _finding(original)

    assert finding.fingerprint == _fingerprint_of(original), (
        "the fingerprint must be derived from the unredacted message"
    )


def test_the_stored_message_is_redacted():
    original = f'Possible hardcoded password: "{SECRET}"'
    finding = _finding(original)

    assert SECRET not in finding.message
    assert MASK in finding.message


def test_the_same_finding_fingerprints_identically_across_runs():
    """Stability is the property the fingerprint exists for: the same
    logical finding must dedupe the same way every run."""
    first = _finding(f'Possible hardcoded password: "{SECRET}"')
    second = _finding(f'Possible hardcoded password: "{SECRET}"')
    assert first.fingerprint == second.fingerprint


def test_two_different_secrets_remain_different_findings():
    """Redacting the stored message must not collapse distinct findings
    into one fingerprint -- they are different findings and a suppression
    of one must not suppress the other."""
    a = _finding('Possible hardcoded password: "sk-live-aaaaaaaaaaaaaaaa"')
    b = _finding('Possible hardcoded password: "sk-live-bbbbbbbbbbbbbbbb"')
    assert a.fingerprint != b.fingerprint
    assert a.message == b.message, "both stored messages are masked identically"


def test_an_ordinary_message_survives_untouched():
    """redact() over-redacts by design, so the precision guard matters:
    a normal scanner message must not acquire a mask."""
    plain = "Possible SQL injection vector through string-based query construction."
    finding = _finding(plain)
    assert finding.message == plain
    assert finding.fingerprint == _fingerprint_of(plain)


# --- amendment 3: the source content sent to the model -----------------


def test_redact_source_masks_a_hardcoded_key():
    source = f'API_KEY = "{SECRET}"\n'
    out = redact_source(source)
    assert SECRET not in out
    assert MASK in out


def test_redact_source_preserves_the_line_count():
    """Findings are line-anchored. A redaction that changes the number of
    lines misplaces every finding below it."""
    source = (
        "import os\n"
        f'TOKEN = "{GH_TOKEN}"\n'
        "def f():\n"
        "    return 1\n"
    )
    out = redact_source(source)
    assert len(out.splitlines()) == len(source.splitlines())
    assert GH_TOKEN not in out
    # The lines around the secret are byte-identical.
    assert out.splitlines()[0] == "import os"
    assert out.splitlines()[2] == "def f():"


def test_a_pem_block_does_not_shift_line_numbers():
    """The specific case plain redact() gets wrong: it collapses a PEM body
    onto one line, so every line after the key moves."""
    source = (
        "HEADER = 1\n"
        "KEY = '''\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAxrDCQ0m1V0Nm7pFqQkq3\n"
        "Zx9YkPqL2mN4oR6sT8uV0wX2yZ4aB6cD8eF0\n"
        "-----END RSA PRIVATE KEY-----\n"
        "'''\n"
        "FOOTER = 2\n"
    )
    out = redact_source(source)

    assert len(out.splitlines()) == len(source.splitlines()), (
        "a PEM block must not change the line count"
    )
    assert "MIIEowIBAAKCAQEAxrDCQ0m1V0Nm7pFqQkq3" not in out
    assert out.splitlines()[0] == "HEADER = 1"
    assert out.splitlines()[-1] == "FOOTER = 2"


def test_plain_redact_would_have_shifted_the_lines():
    """Pins WHY redact_source exists rather than reusing redact().

    If redact() ever becomes line-preserving this fails, and the honest
    response is to delete redact_source, not to weaken this test.
    """
    source = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAxrDCQ0m1V0Nm7pFqQkq3\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    assert len(redact(source).splitlines()) != len(source.splitlines())


def test_ordinary_source_is_returned_unchanged():
    source = (
        "import sqlite3\n"
        "\n"
        "def get_user(cursor, email):\n"
        '    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))\n'
        "    return cursor.fetchone()\n"
    )
    assert redact_source(source) == source


def test_redact_source_handles_empty_and_trailing_newlines():
    assert redact_source("") == ""
    assert redact_source("\n") == "\n"
    assert redact_source("a = 1\n\n\n") == "a = 1\n\n\n"


# --- amendment 3: the captured outbound prompt -------------------------


def _capture_outbound(user_content: str) -> str:
    """What call_agent would actually send to Anthropic.

    Intercepts at client.messages.create, i.e. the last point before the
    request leaves the process, rather than trusting an intermediate
    variable. Anything asserted here is asserted about the network payload.
    """
    from unittest.mock import patch

    from codeguard.pipeline import llm_call

    sent: dict = {}

    class _Msg:
        text = '{"verdicts": []}'
        type = "text"

    class _Resp:
        content = [_Msg()]
        usage = type("U", (), {"input_tokens": 1, "output_tokens": 1,
                               "cache_creation_input_tokens": 0,
                               "cache_read_input_tokens": 0})()
        stop_reason = "end_turn"

    class _Client:
        class messages:
            @staticmethod
            def create(**kwargs):
                sent.update(kwargs)
                return _Resp()

    with patch.object(llm_call, "_build_client", return_value=(_Client(), False)):
        llm_call.call_agent(
            agent="security", api_key="k", system_prompt="sys",
            repo_context="ctx", user_content=user_content,
            model="m", max_tokens=10, timeout=5,
        )

    return sent["messages"][0]["content"]


def test_a_secret_in_source_never_reaches_the_model():
    """The assertion amendment 3 asks for: a secret in a SOURCE FILE is
    absent from the captured prompt.

    The scanner path is not involved -- this key is simply sitting in the
    code, which is how it reaches the model whether or not anything
    flagged it.
    """
    source = (
        "import os\n"
        f'ANTHROPIC_API_KEY = "{SECRET}"\n'
        "def go():\n"
        "    return ANTHROPIC_API_KEY\n"
    )
    outbound = _capture_outbound(source)

    assert SECRET not in outbound, "the secret was sent to Anthropic"
    assert MASK in outbound


def test_a_github_token_in_source_never_reaches_the_model():
    outbound = _capture_outbound(f'TOKEN = "{GH_TOKEN}"\n')
    assert GH_TOKEN not in outbound


def test_the_prompt_keeps_its_line_geometry():
    """Findings are line-anchored, so the content the model reasons about
    must have the same line numbers as the file on disk. A redaction that
    moved them would make every returned line number wrong."""
    source = (
        "line1 = 1\n"
        f'secret = "{SECRET}"\n'
        "line3 = 3\n"
        "line4 = 4\n"
    )
    outbound = _capture_outbound(source)

    assert len(outbound.splitlines()) == len(source.splitlines())
    assert outbound.splitlines()[0] == "line1 = 1"
    assert outbound.splitlines()[2] == "line3 = 3"


def test_ordinary_source_reaches_the_model_untouched():
    """Over-redaction has a cost too: the model has to see real code to
    judge it."""
    source = (
        "import sqlite3\n"
        "def get_user(cursor, email):\n"
        '    cursor.execute("SELECT * FROM users WHERE email = \'%s\'" % email)\n'
    )
    assert _capture_outbound(source) == source
