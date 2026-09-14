"""Runs the real Semgrep/Bandit/Ruff binaries against small known-bad
snippets — not mocked — so a broken CLI invocation or output-parsing
regression is caught here, not only discoverable via a live PR.

Asserting "no internal.tool_unavailable finding" rather than asserting
specific findings came back is deliberate: base.py's harness swallows
every exception (including a parsing bug) into that fallback finding, so
a naive "did it crash" test would pass even with broken parsing. This
is the assertion that actually proves the real subprocess ran AND this
module's own parsing succeeded.

Phase 4.1: each runner now takes a `files: dict[path, content]` and is
invoked once for a whole "PR" (possibly one file), not per file — these
tests exercise that multi-file path directly, including the path being
correctly resolved back from the tool's temp-directory-relative report
to the original relative path.
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

# Real content from rules/llm-security.yaml's own domain (Phase 6) — a
# floating model alias, no system prompt, no max_tokens. Semgrep's role
# since Phase 4.1 is custom rulesets only (Bandit owns generic security);
# this exercises that real ruleset, not a placeholder.
LLM_CALL_SNIPPET = '''\
import anthropic

client = anthropic.Anthropic()


def ask(question):
    return client.messages.create(model="claude-3-5-sonnet-latest", messages=[{"role": "user", "content": question}])
'''


def _ran_successfully(findings):
    return not any(f.rule_id == "internal.tool_unavailable" for f in findings)


def test_bandit_runs_and_finds_the_sql_injection():
    findings = run_bandit({"app/db.py": SQL_INJECTION_SNIPPET})
    assert _ran_successfully(findings), findings
    assert any(f.rule_id.startswith("B6") for f in findings), findings  # B608: SQL injection
    for f in findings:
        assert f.file == "app/db.py"
        assert f.start_line > 0


def test_bandit_partitions_findings_across_multiple_files_correctly():
    """The core Phase 4.1 guarantee: one invocation over several files
    must attribute each finding back to the RIGHT original file, not
    just any file that happened to be in the batch.
    """
    findings = run_bandit({
        "app/db.py": SQL_INJECTION_SNIPPET,
        "app/clean.py": "def add(a: int, b: int) -> int:\n    return a + b\n",
    })
    assert _ran_successfully(findings), findings
    files_with_findings = {f.file for f in findings}
    assert files_with_findings == {"app/db.py"}


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="semgrep's native scanning engine isn't available under this Windows "
           "install — confirmed by invoking it directly outside this test harness, "
           "which shows the identical os.execvp/FileNotFoundError failure. The "
           "actual deployment target is Linux containers, where this doesn't occur; "
           "verified separately there, not skipped on faith.",
)
def test_semgrep_runs_llm_security_ruleset_and_catches_unpinned_model():
    findings = run_semgrep({"app/assistant.py": LLM_CALL_SNIPPET})
    assert _ran_successfully(findings), findings
    rule_ids = {f.rule_id for f in findings}
    assert "rules.llm-unpinned-model-alias" in rule_ids or "llm-unpinned-model-alias" in rule_ids, findings
    for f in findings:
        assert f.file == "app/assistant.py"


def test_ruff_runs_and_parses_successfully():
    findings = run_ruff({"app/db.py": SQL_INJECTION_SNIPPET})
    assert _ran_successfully(findings), findings
    for f in findings:
        assert f.file == "app/db.py"


def test_a_clean_file_produces_no_bandit_findings():
    clean = "def add(a: int, b: int) -> int:\n    return a + b\n"
    findings = run_bandit({"app/utils.py": clean})
    assert _ran_successfully(findings), findings
    assert findings == []
