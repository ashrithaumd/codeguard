"""Runs the real Semgrep/Bandit/Ruff binaries against a small known-bad
snippet — not mocked — so a broken CLI invocation or output-parsing
regression is caught here, not only discoverable via a live PR.

Asserting "no internal.tool_unavailable finding" rather than asserting
specific findings came back is deliberate: base.py's harness swallows
every exception (including a parsing bug) into that fallback finding, so
a naive "did it crash" test would pass even with broken parsing. This
is the assertion that actually proves the real subprocess ran AND this
module's own parsing succeeded.
"""

import sys

import pytest

from codeguard.tools.bandit_runner import run_bandit
from codeguard.tools.ruff_runner import run_ruff
from codeguard.tools.semgrep_runner import run_semgrep

SQL_INJECTION_SNIPPET = '''\
import sqlite3

DB_PASSWORD = "admin123"


def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
'''


def _ran_successfully(findings):
    return not any(f.rule_id == "internal.tool_unavailable" for f in findings)


def test_bandit_runs_and_finds_the_sql_injection():
    findings = run_bandit("app/db.py", SQL_INJECTION_SNIPPET)
    assert _ran_successfully(findings), findings
    assert any(f.rule_id.startswith("B6") for f in findings), findings  # B608: SQL injection
    for f in findings:
        assert f.file == "app/db.py"
        assert f.start_line > 0


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="semgrep's native scanning engine isn't available under this Windows "
           "install — confirmed by invoking it directly outside this test harness, "
           "which shows the identical os.execvp/FileNotFoundError failure. The "
           "actual deployment target is Linux containers, where this doesn't occur; "
           "verified separately there, not skipped on faith.",
)
def test_semgrep_runs_and_parses_successfully():
    findings = run_semgrep("app/db.py", SQL_INJECTION_SNIPPET)
    assert _ran_successfully(findings), findings
    for f in findings:
        assert f.file == "app/db.py"


def test_ruff_runs_and_parses_successfully():
    findings = run_ruff("app/db.py", SQL_INJECTION_SNIPPET)
    assert _ran_successfully(findings), findings
    for f in findings:
        assert f.file == "app/db.py"


def test_a_clean_file_produces_no_bandit_findings():
    clean = "def add(a: int, b: int) -> int:\n    return a + b\n"
    findings = run_bandit("app/utils.py", clean)
    assert _ran_successfully(findings), findings
    assert findings == []
