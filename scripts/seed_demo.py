"""SAMPLE DATA for exploring the dashboard locally.

Replaces scripts/seed_dashboard_fixtures.py and the uncommitted
seed_sample_data.py it was later run alongside. Two things changed.

SELF-CONSISTENT. The old scripts hand-entered every count, so the
dashboard showed numbers the real writer cannot produce -- "9 dismissed"
over an empty list, a banner saying 48 files were skipped over a list of
five -- and those were reported, reasonably, as dashboard bugs. Every
count here is DERIVED from the list it describes, exactly as
pipeline/reviews.py derives it, and build_review_row() checks the
invariants before anything is written. tests/tooling/test_seed_demo.py holds it
to that without a database.

ON REAL REPOS, LABELLED. The Reviews list and repo pages only show rows for
repositories GitHub confirms the viewer can access, so a fake owner never
renders for anyone. The rows go on the operator's own installed repos
instead, and are labelled so they cannot be mistaken for real reviews:

  - every pr_title starts with "[SAMPLE]"
  - every summary_body and audit report starts with "SAMPLE DATA"
  - every finding message and dismissal reason starts with "SAMPLE."
  - PR numbers are 9001+, which no real PR in these repos uses
  - every job_id and audit id is uuid5(SAMPLE_NS, ...), so --remove is exact

Refuses any DATABASE_URL whose host is not local.

    docker compose exec api python /app/scripts/seed_demo.py
    docker compose exec api python /app/scripts/seed_demo.py --remove
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

SAMPLE_NS = uuid.UUID("5a3b1e00-c0de-4a00-9a00-5a3b1e5a3b1e")
LABEL = "SAMPLE DATA - not a real review. Seeded locally to explore the dashboard."
AUDIT_LABEL = "SAMPLE DATA - not a real audit. Seeded locally to explore the dashboard."
# The owner seed_dashboard_fixtures.py wrote under. Its rows never rendered
# (no viewer can access a fake owner), but --remove clears them too.
LEGACY_FIXTURE_OWNER = "codeguard-fixtures"
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "db", "postgres"}

# Kept in step with codeguard.report_format by tests/tooling/test_seed_demo.py,
# without importing the package -- this script runs as a file.
REPORT_DATA_VERSION = 1

# The reasons diff/filters.py and diff/ingest.py actually write.
R_BUDGET_FILES = "dropped by max_files budget"
R_GENERATED = "lockfile/generated/docs/vendored"
R_NON_PYTHON = "non-Python (v1 scope is Python-only)"
# The multi-language reasons (codeguard/languages.py, tools/zizmor_runner.py).
R_NOT_COVERED = "Not covered by any scanner ({})"
R_INVALID_YAML = "not scanned (invalid YAML)"

# Source tools by the reviews table's buckets (migration 006).
_VERDICT_AGENTS = {"security", "ai_aware", "security_generic"}
_GENERATIVE = {"quality-agent", "test-agent"}
# Reported as the scanner found them, never judged: pipeline/reviews.py
# counts these "unverified" (a secret decided by its shape, a LOW passed
# through). None of the Python-era sample rows uses them.
_UNJUDGED_SCANNERS = {"gitleaks", "zizmor", "gitlab-sast", "codeguard-rules"}


def _assert_local(dsn: str) -> None:
    host = (urlsplit(dsn).hostname or "").lower()
    if host not in _LOCAL_HOSTS:
        sys.exit(
            f"refusing to seed: DATABASE_URL points at {host!r}, which is not a local database "
            f"({', '.join(sorted(_LOCAL_HOSTS))}). Sample data must never reach a real deployment."
        )


def sid(*parts) -> uuid.UUID:
    return uuid.uuid5(SAMPLE_NS, "/".join(map(str, parts)))


def sha(*parts) -> str:
    return (sid("sha", *parts).hex + sid("sha2", *parts).hex)[:40]


def finding(path, line, sev, tool, rule, msg):
    return {"file": path, "start_line": line, "end_line": line, "severity": sev,
            "source_tool": tool, "rule_id": rule, "message": "SAMPLE. " + msg,
            "fingerprint": sid(path, line, rule).hex[:16], "confidence": 1.0}


def dismissal(path, line, rule, reason):
    """The DismissedFinding shape -- not a finding's. The old sample data
    stored finding dicts here, which the page could not show a reason for."""
    return {"file": path, "start_line": line, "rule_id": rule, "reason": "SAMPLE. " + reason}


def review_templates() -> list[dict]:
    sql = finding("app/db.py", 42, "CRITICAL", "security", "B608",
                  "SQL query built with an f-string from request input reaches cursor.execute().")
    llm = finding("app/chat.py", 31, "HIGH", "ai_aware", "llm-prompt-injection-concatenation",
                  "User-controlled text is concatenated into the prompt (OWASP LLM01).")
    to = finding("app/chat.py", 58, "MEDIUM", "ai_aware", "llm-call-missing-timeout",
                 "Anthropic call made without a timeout; a hung call blocks the worker.")
    sql_fix = {
        "fingerprint": sql["fingerprint"],
        "suggestion_body": '```suggestion\n    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))\n```',
        "target_file": "app/db.py", "target_line": 42, "target_end_line": 42,
        "original_text": '    cursor.execute(f"SELECT * FROM users WHERE email = \'{email}\'")',
    }
    test_asserts = [dismissal("tests/test_db.py", n, "B101",
                              "An assert in a test file is the test, not a production check.")
                    for n in (12, 19, 27)]
    return [
        # One PR reviewed three times: blocked, still blocked, then fixed.
        dict(pr=9001, title="Add user lookup endpoint and chat assistant", action="opened",
             conclusion="failure", age=timedelta(days=3, hours=4), gate="HIGH", fix="HIGH",
             files_reviewed=12, inline=5, tokens=(41_250, 5_310), cost=0.3412, duration=88.6,
             findings=[sql, llm,
                       finding("app/chat.py", 74, "MEDIUM", "quality-agent", "quality.error-handling",
                               "Broad `except Exception: pass` hides API failures from the caller."),
                       finding("app/users.py", 18, "MEDIUM", "test-agent", "test.test",
                               "New lookup_by_email() has no accompanying test."),
                       finding("requirements.txt", 7, "HIGH", "osv", "GHSA-j8r2-6x86-q33q",
                               "requests 2.25.1 leaks Proxy-Authorization headers on redirect."),
                       finding("app/util.py", 12, "LOW", "bandit", "B311",
                               "random.random() used where a token is generated.")],
             fix_suggestions=[sql_fix],
             dismissed=[dismissal("app/settings.py", 5, "B105",
                                  "The value 'changeme' is placeholder-shaped, not a credential.")] + test_asserts,
             filtered=[{"path": "README.md", "reason": R_GENERATED},
                       {"path": "poetry.lock", "reason": R_GENERATED},
                       {"path": "web/app.js", "reason": R_NON_PYTHON},
                       {"path": "web/style.css", "reason": R_NON_PYTHON},
                       {"path": "docs/api.md", "reason": R_GENERATED},
                       {"path": "docs/chat.md", "reason": R_GENERATED}],
             latencies=[{"node": "review_security", "file": "app/db.py", "seconds": 11.8},
                        {"node": "review_ai_aware", "file": "app/chat.py", "seconds": 9.3},
                        {"node": "summarize", "file": "", "seconds": 2.9}],
             summary="Blocked: 1 critical and 2 high severity findings."),
        dict(pr=9001, title="Add user lookup endpoint and chat assistant", action="synchronize",
             conclusion="failure", age=timedelta(days=3, hours=2), gate="HIGH", fix="HIGH",
             files_reviewed=12, inline=3, tokens=(9_870, 1_420), cost=0.0815, duration=31.2,
             findings=[sql, llm, to], fix_suggestions=[sql_fix], dismissed=test_asserts,
             filtered=[{"path": "README.md", "reason": R_GENERATED},
                       {"path": "poetry.lock", "reason": R_GENERATED},
                       {"path": "web/app.js", "reason": R_NON_PYTHON},
                       {"path": "web/style.css", "reason": R_NON_PYTHON},
                       {"path": "docs/api.md", "reason": R_GENERATED},
                       {"path": "docs/chat.md", "reason": R_GENERATED}],
             summary="Still blocked after the second push; most hunks served from the cache."),
        dict(pr=9001, title="Add user lookup endpoint and chat assistant", action="synchronize",
             conclusion="success", age=timedelta(days=2, hours=22), gate="HIGH", fix="HIGH",
             files_reviewed=12, inline=1, tokens=(7_015, 980), cost=0.0592, duration=24.7,
             findings=[to], dismissed=test_asserts,
             filtered=[{"path": "README.md", "reason": R_GENERATED},
                       {"path": "poetry.lock", "reason": R_GENERATED},
                       {"path": "web/app.js", "reason": R_NON_PYTHON},
                       {"path": "web/style.css", "reason": R_NON_PYTHON},
                       {"path": "docs/api.md", "reason": R_GENERATED},
                       {"path": "docs/chat.md", "reason": R_GENERATED}],
             summary="Passing: the SQL injection and prompt injection were fixed."),
        # Budget-capped big PR with a failed verdict call. 63 changed files,
        # 15 reviewed, and all 48 others itemised -- by the budget and by
        # the path filters -- as the real ingest would.
        dict(pr=9002, title="Refactor ingestion pipeline into async workers", action="opened",
             conclusion="failure", age=timedelta(hours=20), gate="HIGH", fix="HIGH",
             files_reviewed=15, inline=3, tokens=(52_400, 6_880), cost=0.4419, duration=117.9,
             findings=[finding("ingest/worker.py", 120, "HIGH", "security", "B602",
                               "subprocess call with shell=True using a filename from the queue payload."),
                       finding("ingest/retry.py", 33, "MEDIUM", "quality-agent", "quality.concurrency",
                               "Retry counter is shared across tasks without a lock."),
                       finding("ingest/__init__.py", 3, "LOW", "ruff", "F401", "`os` imported but unused."),
                       finding("ingest/parse.py", 88, "MEDIUM", "security", "B307",
                               "eval() on a value read from the payload.")],
             dismissed=[dismissal(f"tests/ingest/test_worker_{i}.py", 10 + i, "B101",
                                  "An assert in a test file is the test, not a production check.")
                        for i in range(1, 8)]
                       + [dismissal("ingest/config.py", 4, "B108",
                                    "/tmp is used only as a default overridden by INGEST_TMP in every deployment."),
                          dismissal("ingest/hashing.py", 9, "B324",
                                    "md5 is used for a cache key, not for anything security-relevant.")],
             filtered=[{"path": f"ingest/legacy/mod_{i:02d}.py", "reason": R_BUDGET_FILES} for i in range(1, 41)]
                      + [{"path": f"docs/ingest/{n}.md", "reason": R_GENERATED}
                         for n in ("overview", "queue", "retries", "workers", "metrics")]
                      + [{"path": "ingest/schema.json", "reason": R_NON_PYTHON},
                         {"path": "ingest/Dockerfile", "reason": R_NON_PYTHON},
                         {"path": "uv.lock", "reason": R_GENERATED}],
             failures=[{"path": "ingest/parse.py", "agent": "security",
                        "reason": "APITimeoutError: request timed out"}],
             summary="Blocked: 1 high severity finding. Budget cap reached; 48 files not reviewed."),
        # Clean PR.
        dict(pr=9003, title="Fix typo in quickstart docs", action="opened",
             conclusion="success", age=timedelta(hours=6), gate="CRITICAL", fix="HIGH",
             files_reviewed=1, inline=0, tokens=(1_053, 138), cost=0.0046, duration=13.5,
             findings=[], filtered=[{"path": "docs/quickstart.md", "reason": R_GENERATED}],
             summary="Nothing found."),
        dict(pr=9004, title="Pin dependencies and add CI lint step", action="opened",
             conclusion="success", age=timedelta(days=6), gate="HIGH", fix="HIGH",
             files_reviewed=3, inline=2, tokens=(3_920, 512), cost=0.0198, duration=19.1,
             findings=[finding("ci/lint.py", 14, "MEDIUM", "ruff", "E722", "Bare `except:` in the lint step."),
                       finding("requirements.txt", 3, "LOW", "osv", "PYSEC-2023-0001",
                               "Low-severity advisory in a transitive dependency.")],
             dismissed=[dismissal("ci/lint.py", 2, "B404",
                                  "subprocess is imported to run ruff with a fixed argument list.")],
             filtered=[{"path": ".github/workflows/ci.yml", "reason": R_NON_PYTHON}],
             summary="Passing with 2 low/medium findings."),
    ] + multilanguage_review_templates()


def multilanguage_review_templates() -> list[dict]:
    """A PR across every covered language, reviewed twice: the first push
    with findings in each and the dependency CVEs; the second with OSV
    unreachable -- the "Dependency CVE check unavailable" note and, as in a
    real review, no dependency finding at all (both checks need OSV)."""
    inj = finding("src/assistant.ts", 15, "HIGH", "security_generic", "codeguard-js-llm-prompt-injection-concatenation",
                  "The ticket body is concatenated into the prompt one line above the call (OWASP LLM01).")
    js_eval = finding("web/render.js", 22, "HIGH", "security_generic", "javascript_eval_rule-eval-with-expression",
                      "eval() runs a template string built from the request query.")
    go_tls = finding("client/http.go", 31, "HIGH", "security_generic", "codeguard-go-tls-insecure-skip-verify",
                     "tls.Config sets InsecureSkipVerify: true for the billing API client.")
    java = finding("worker/src/main/java/jobs/Export.java", 48, "HIGH", "security_generic",
                   "java_inject_rule-CommandInjection", "A job parameter reaches ProcessBuilder through a shell.")
    csharp = finding("api/Controllers/ReportsController.cs", 57, "HIGH", "security_generic",
                     "csharp_injection_rule-SQLInjection", "The report filter is concatenated into SqlCommand text.")
    secret = finding("config/deploy.yaml", 12, "HIGH", "gitleaks", "gitleaks.github-pat",
                     "Hardcoded secret (github-pat): 40-char github-style token, high-entropy.")
    docker = finding("Dockerfile", 9, "HIGH", "security_generic", "codeguard-dockerfile-curl-pipe-shell",
                     "An install script is downloaded with curl and piped straight into sh.")
    actions = finding(".github/workflows/triage.yml", 18, "HIGH", "security_generic", "template-injection",
                      "${{ github.event.issue.title }} is expanded inside a run: script.")
    unpinned = finding(".github/workflows/ci.yml", 7, "LOW", "zizmor", "unpinned-uses",
                       "actions/checkout is referenced by tag, not by commit SHA.")
    cve_npm = finding("web/package-lock.json", 1432, "HIGH", "osv", "GHSA-p6mc-m468-83gw",
                      "lodash@4.17.15 has a known vulnerability (GHSA-p6mc-m468-83gw): Prototype Pollution "
                      "in lodash. Fixed in 4.17.19.")
    cve_go = finding("go.mod", 7, "MEDIUM", "osv", "GO-2021-0052",
                     "github.com/gin-gonic/gin@1.6.0 has a known vulnerability (GO-2021-0052): Inconsistent "
                     "interpretation of HTTP requests. Fixed in 1.7.0.")
    hygiene = finding("<repo>", 0, "MEDIUM", "eval-hygiene", "eval-hygiene.missing-evals-js",
                      "1 JavaScript/TypeScript file(s) call an LLM SDK (src/assistant.ts) but this repo has no "
                      "evals/ directory, no eval-framework files (promptfoo, evalite) and no test that asserts "
                      "on LLM output.")
    jitter = dismissal("client/backoff.go", 14, "go_crypto_rule-weakrandsource",
                       "math/rand only spreads retry jitter; nothing secret is derived from it.")
    filtered = [{"path": "android/app/src/main/java/MainActivity.kt", "reason": R_NOT_COVERED.format("Kotlin")},
                {"path": "android/app/build.gradle.kts", "reason": R_NOT_COVERED.format("Kotlin")},
                {"path": "ios/App/AppDelegate.swift", "reason": R_NOT_COVERED.format("Swift")},
                {"path": "scripts/release.rb", "reason": R_NOT_COVERED.format("Ruby")},
                {"path": ".github/workflows/nightly.yml", "reason": R_INVALID_YAML},
                {"path": "web/package-lock.json", "reason": R_GENERATED},
                {"path": "docs/architecture.md", "reason": R_GENERATED}]
    coverage = "Not covered by any scanner: Kotlin 2, Ruby 1, Swift 1."
    return [
        dict(pr=9005, title="Add Node assistant, Go billing client, Java export worker and C# reports API",
             action="opened", conclusion="failure", age=timedelta(hours=9), gate="HIGH", fix="HIGH",
             files_reviewed=11, inline=8, tokens=(18_420, 2_960), cost=0.1240, duration=64.2,
             findings=[inj, js_eval, go_tls, java, csharp, secret, docker, actions, unpinned, cve_npm, cve_go, hygiene],
             dismissed=[jitter], filtered=filtered,
             latencies=[{"node": "review_security_generic", "file": "src/assistant.ts", "seconds": 7.4},
                        {"node": "review_security_generic", "file": "api/Controllers/ReportsController.cs", "seconds": 6.1},
                        {"node": "summarize", "file": "", "seconds": 2.2}],
             summary=f"Blocked: 9 high severity findings.\n\n{coverage}"),
        dict(pr=9005, title="Add Node assistant, Go billing client, Java export worker and C# reports API",
             action="synchronize", conclusion="failure", age=timedelta(hours=7), gate="HIGH", fix="HIGH",
             files_reviewed=11, inline=4, tokens=(9_310, 1_480), cost=0.0611, duration=41.8,
             findings=[java, csharp, secret, actions, unpinned, hygiene], dismissed=[jitter], filtered=filtered,
             dependency_check_unavailable=True,
             summary=("Still blocked: 4 high severity findings. The prompt injection, eval, TLS and Dockerfile "
                      f"findings are fixed.\n\nCaution: Dependency CVE check unavailable.\n\n{coverage}")),
    ]


def build_review_row(t: dict) -> dict:
    """A template plus everything DERIVED from it, the way the real writer
    derives it. Raises if the template contradicts itself, so impossible
    numbers cannot reach the dashboard."""
    findings = t.get("findings", [])
    failed_paths = {f["path"] for f in t.get("failures", [])}
    vc = sum(1 for f in findings if f["source_tool"] in _VERDICT_AGENTS and f["file"] not in failed_paths)
    unv = sum(1 for f in findings if f["source_tool"] in _VERDICT_AGENTS and f["file"] in failed_paths)
    unv += sum(1 for f in findings if f["source_tool"] in _UNJUDGED_SCANNERS)
    gen = sum(1 for f in findings if f["source_tool"] in _GENERATIVE)
    det = len(findings) - vc - unv - gen
    filtered = t.get("filtered", [])
    unique_filtered = {f["path"] for f in filtered}
    row = {
        **t,
        "title": "[SAMPLE] " + t["title"],
        "summary": f"{LABEL}\n\n{t['summary']}",
        "findings": findings,
        "dismissed_json": t.get("dismissed", []),
        "dismissed_count": len(t.get("dismissed", [])),
        "filtered": filtered,
        "files_seen": t["files_reviewed"] + len(unique_filtered),
        "findings_total": len(findings),
        "buckets": (vc, gen, det, unv),
        "fix_suggestions": t.get("fix_suggestions", []),
        "fix_suggestion_count": len(t.get("fix_suggestions", [])),
        "inline_count": t["inline"],
        "budget_exceeded": any("budget" in f["reason"] for f in filtered),
        "dependency_check_unavailable": t.get("dependency_check_unavailable", False),
    }
    if row["inline_count"] > row["findings_total"]:
        raise ValueError(f"PR {t['pr']}: {row['inline_count']} inline comments for {row['findings_total']} findings")
    return row


# --------------------------------------------------------------------------
# The sample audit, as both the markdown and the structured report the
# audit page renders (cli.build_report_data's shape).
# --------------------------------------------------------------------------

_AUDIT_FINDINGS = [
    dict(severity="high", title="SQL built with an f-string", file="app/db.py", start_line=42, end_line=42,
         what="SAMPLE. The email parameter is interpolated into the query text.",
         why="An email like ' OR '1'='1 returns every row in the table.",
         fix="Pass the value as a bound parameter: execute(sql, (email,)).",
         rules=["B608"], source_tool="security"),
    dict(severity="medium", title="User input concatenated into the prompt", file="app/chat.py",
         start_line=31, end_line=31,
         what="SAMPLE. The ticket text is concatenated onto the instruction string.",
         why="Text in the ticket can override the instructions it is appended to.",
         fix="Send the ticket as its own delimited block, with instructions in system=.",
         rules=["llm-prompt-injection-concatenation"], source_tool="ai_aware"),
    dict(severity="medium", title="No timeout on the model call", file="app/chat.py", start_line=58, end_line=58,
         what="SAMPLE. messages.create() is called without timeout=.",
         why="A hung connection holds the worker indefinitely.", fix="Pass timeout= on the call or the client.",
         rules=["llm-call-missing-timeout"], source_tool="ai_aware"),
    dict(severity="medium", title="Shared retry counter without a lock", file="ingest/retry.py",
         start_line=33, end_line=33, what="SAMPLE. Tasks increment one counter concurrently.",
         why="", fix="", rules=["quality.concurrency"], source_tool="quality-agent"),
    dict(severity="low", title="Unused import", file="ingest/__init__.py", start_line=3, end_line=3,
         what="SAMPLE. `os` is imported but unused.", why="", fix="", rules=["F401"], source_tool="ruff"),
    dict(severity="low", title="Non-cryptographic random for a token", file="app/util.py",
         start_line=12, end_line=12, what="SAMPLE. random.random() generates a session token.",
         why="Its output is predictable.", fix="Use secrets.token_urlsafe().", rules=["B311"], source_tool="bandit"),
]
_AUDIT_DISMISSED = [
    {"file": "app/settings.py", "start_line": 5, "rule_id": "B105",
     "reason": "SAMPLE. The value 'changeme' is placeholder-shaped, not a credential."},
]


def sample_audit_report_json(owner: str, repo: str) -> dict:
    counts = {k: 0 for k in ("critical", "high", "medium", "low")}
    for f in _AUDIT_FINDINGS:
        counts[f["severity"]] += 1
    findings = [{**f, "message": f["what"]} for f in _AUDIT_FINDINGS]
    return {
        "version": REPORT_DATA_VERSION,
        "target": f"https://github.com/{owner}/{repo}",
        "summary": {"files_scanned": 47, "files_ai_aware": 3, "total": len(findings), "counts": counts,
                    "repo_level": 0, "dismissed": len(_AUDIT_DISMISSED), "skipped_test_asserts": 12},
        "incomplete": [],
        "findings": findings,
        "repo_level": [],
        "dismissed": _AUDIT_DISMISSED,
        "skipped_files": [],
        "verdict_call_failures": [],
        "technical": {"tokens_in": 24_310, "tokens_out": 3_105, "estimated_cost_usd": 0.2140,
                      "elapsed_s": 142.6, "models": {"security": "sample", "ai_aware": "sample"}},
    }


def sample_audit_markdown(owner: str, repo: str) -> str:
    data = sample_audit_report_json(owner, repo)
    lines = [f"# CodeGuard audit: {data['target']}", "", f"> {AUDIT_LABEL}", ""]
    for f in data["findings"]:
        lines.append(f"- `{f['file']}:{f['start_line']}` [{', '.join(f['rules'])}] {f['what']}")
    return "\n".join(lines) + "\n"


def multilanguage_audit(owner: str, repo: str, osv_unavailable: bool) -> tuple[str, dict]:
    """(markdown, report_json) for a multi-language sample audit, built by
    the REAL report builder (cli.build_report_data / render_report) so the
    page renders exactly what a real audit stores. With osv_unavailable,
    OSV could not be reached: the note, and no dependency finding."""
    from codeguard.cli import build_report_data, render_report
    from codeguard.pipeline.models import DismissedFinding
    from codeguard.severity import Severity
    from codeguard.tools.models import Finding

    # An explicit title per finding, as the Python sample audit has. Without
    # one the card title is the first sentence of `what` (or the message),
    # which the SAMPLE label made "SAMPLE". The label stays on `message`.
    titles = {
        "codeguard-js-llm-prompt-injection-concatenation": "Ticket text concatenated into the prompt",
        "codeguard-js-llm-call-missing-timeout": "No timeout on the Anthropic client",
        "javascript_eval_rule-eval-with-expression": "Request input passed to eval()",
        "codeguard-go-tls-insecure-skip-verify": "TLS certificate verification turned off",
        "java_inject_rule-CommandInjection": "Job parameter reaches a shell command",
        "csharp_injection_rule-SQLInjection": "Report filter concatenated into SQL",
        "codeguard-dockerfile-curl-pipe-shell": "Install script piped from curl into sh",
        "template-injection": "Issue title expanded inside a run: script",
        "gitleaks.github-pat": "Hardcoded GitHub token",
        "unpinned-uses": "Action referenced by tag, not commit SHA",
        "GHSA-p6mc-m468-83gw": "Vulnerable lodash version",
        "GO-2021-0052": "Vulnerable gin version",
        "GHSA-jfh8-c2jp-5v3q": "Vulnerable log4j-core version",
        "GHSA-5crp-9r3c-p9vr": "Vulnerable Newtonsoft.Json version",
        "eval-hygiene.missing-evals-js": "LLM-calling JS/TS code with no evals",
    }

    def f(path, line, sev, tool, rule, msg, what="", why="", fix=""):
        return Finding.create(file=path, start_line=line, end_line=line, severity=Severity[sev],
                              source_tool=tool, rule_id=rule, message="SAMPLE. " + msg,
                              title=titles[rule], what=what, why=why, fix=fix)

    judged = [
        f("src/assistant.ts", 15, "HIGH", "security_generic", "codeguard-js-llm-prompt-injection-concatenation",
          "Ticket text is concatenated into the prompt.", "The ticket body is spliced into the prompt string "
          "one line above messages.create().", "Text in the ticket can override the instructions it is appended to.",
          "Send the ticket as its own delimited block, with the instructions in system."),
        f("src/assistant.ts", 4, "MEDIUM", "security_generic", "codeguard-js-llm-call-missing-timeout",
          "The Anthropic client has no timeout.", "new Anthropic() is constructed with no timeout.",
          "A hung connection holds the request for the SDK default of ten minutes.", "Pass timeout to the client."),
        f("web/render.js", 22, "HIGH", "security_generic", "javascript_eval_rule-eval-with-expression",
          "eval() runs a template built from the request query.", "eval() runs a string built from req.query.",
          "Anyone who can send a request can run code in the server.", "Render with a template engine; never eval."),
        f("client/http.go", 31, "HIGH", "security_generic", "codeguard-go-tls-insecure-skip-verify",
          "Certificate verification is turned off.", "tls.Config sets InsecureSkipVerify: true.",
          "Anyone on the network path can impersonate the billing API.", "Remove InsecureSkipVerify."),
        f("worker/src/main/java/jobs/Export.java", 48, "HIGH", "security_generic", "java_inject_rule-CommandInjection",
          "A job parameter reaches a shell command.", "The export name is passed to sh -c.",
          "A crafted name runs arbitrary commands on the worker.", "Pass arguments as a list, without a shell."),
        f("api/Controllers/ReportsController.cs", 57, "HIGH", "security_generic", "csharp_injection_rule-SQLInjection",
          "The report filter is concatenated into SQL.", "The filter is concatenated into SqlCommand text.",
          "A crafted filter reads or changes any table.", "Use SqlParameter for the filter."),
        f("Dockerfile", 9, "HIGH", "security_generic", "codeguard-dockerfile-curl-pipe-shell",
          "curl output is piped into sh.", "An install script is downloaded and run unverified.",
          "Whoever controls that URL controls the image.", "Download, verify a checksum, then run."),
        f(".github/workflows/triage.yml", 18, "HIGH", "security_generic", "template-injection",
          "An issue title is expanded inside a run: script.",
          "${{ github.event.issue.title }} is expanded in run:.",
          "Anyone who opens an issue can run commands in the workflow.", "Pass it through env: and quote it."),
    ]
    passthrough = [
        f("config/deploy.yaml", 12, "HIGH", "gitleaks", "gitleaks.github-pat",
          "Hardcoded secret (github-pat): 40-char github-style token, high-entropy."),
        f(".github/workflows/ci.yml", 7, "LOW", "zizmor", "unpinned-uses",
          "actions/checkout is referenced by tag, not by commit SHA."),
    ]
    osv = [] if osv_unavailable else [
        f("web/package-lock.json", 1432, "HIGH", "osv", "GHSA-p6mc-m468-83gw",
          "lodash@4.17.15 has a known vulnerability (GHSA-p6mc-m468-83gw): Prototype Pollution in lodash. "
          "Fixed in 4.17.19."),
        f("go.mod", 7, "MEDIUM", "osv", "GO-2021-0052",
          "github.com/gin-gonic/gin@1.6.0 has a known vulnerability (GO-2021-0052): Inconsistent "
          "interpretation of HTTP requests. Fixed in 1.7.0."),
        f("worker/pom.xml", 41, "CRITICAL", "osv", "GHSA-jfh8-c2jp-5v3q",
          "org.apache.logging.log4j:log4j-core@2.14.1 has a known vulnerability (GHSA-jfh8-c2jp-5v3q): "
          "Remote code injection in Log4j. Fixed in 2.15.0."),
        f("api/packages.lock.json", 88, "HIGH", "osv", "GHSA-5crp-9r3c-p9vr",
          "Newtonsoft.Json@12.0.1 has a known vulnerability (GHSA-5crp-9r3c-p9vr): Improper handling of "
          "exceptional conditions. Fixed in 13.0.1."),
    ]
    hygiene = [f("<repo>", 0, "MEDIUM", "eval-hygiene", "eval-hygiene.missing-evals-js",
                 "1 JavaScript/TypeScript file(s) call an LLM SDK (src/assistant.ts) but this repo has no evals/ "
                 "directory, no eval-framework files (promptfoo, evalite) and no test that asserts on LLM output.")]
    kwargs = dict(
        target=f"https://github.com/{owner}/{repo}", files_scanned=38, files_ai_aware=0,
        ai_reviewed_findings=judged, passthrough_findings=passthrough,
        dismissed=[DismissedFinding(file="client/backoff.go", start_line=14, rule_id="go_crypto_rule-weakrandsource",
                                    reason="SAMPLE. math/rand only spreads retry jitter; nothing secret is derived "
                                           "from it.")],
        eval_hygiene_findings=hygiene, osv_findings=osv,
        skipped_files=[(".github/workflows/nightly.yml", R_INVALID_YAML),
                       ("web/public/vendor.bundle.js", "too large to scan (over 256 KB)")],
        verdict_call_failures=[], unavailable_tools=[],
        tokens_in=21_870, tokens_out=3_340, estimated_cost_usd=0.1532, elapsed_s=118.4,
        models={"security_generic": "sample"},
        not_covered=[{"language": "Kotlin", "paths": ["android/app/build.gradle.kts",
                                                      "android/app/src/main/java/MainActivity.kt"]},
                     {"language": "Ruby", "paths": ["scripts/release.rb"]},
                     {"language": "Swift", "paths": ["ios/App/AppDelegate.swift"]}],
        secret_placeholders=2,
        tool_warnings=["Dependency CVE check unavailable"] if osv_unavailable else [],
    )
    data = build_report_data(**kwargs)
    markdown = render_report(**kwargs)
    heading, _, rest = markdown.partition("\n")
    return f"{heading}\n\n> {AUDIT_LABEL}\n{rest}", data


# --------------------------------------------------------------------------

_INSERT = """
INSERT INTO reviews (
    job_id, owner, repo, pr_number, head_sha, action, private,
    summary_body, check_conclusion, gate_threshold, fix_threshold,
    files_seen, files_reviewed, findings_total,
    findings_verdict_confirmed, findings_generative, findings_deterministic, findings_unverified,
    dismissed_count, inline_count, fix_suggestion_count,
    budget_exceeded, filtered_files_json, pr_title,
    tokens_in, tokens_out, estimated_cost_usd, duration_s,
    node_latencies_json, findings_json, dismissed_json,
    fix_suggestions_json, verdict_call_failures_json, created_at, dependency_check_unavailable
) VALUES (%s,%s,%s,%s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s, %s,%s,%s,%s,
          %s,%s,%s, %s,%s,%s, %s,%s,%s,%s, %s,%s,%s, %s,%s,%s, %s)
"""

_REMOVE = (
    "DELETE FROM reviews WHERE summary_body LIKE 'SAMPLE DATA%%'",
    "DELETE FROM reviews WHERE summary_body LIKE 'FIXTURE%%'",
    "DELETE FROM reviews WHERE owner = %(legacy)s",
    "DELETE FROM audits WHERE report_markdown LIKE '%%SAMPLE DATA - not a real audit%%' "
    "OR error LIKE 'SAMPLE DATA%%'",
)


def target_repos(requester: str) -> list[dict]:
    """The operator's installed repos, public first (audits need public)."""
    from codeguard.api import access
    repos = [r for r in access.installed_repositories() if r["owner"].lower() == requester.lower()]
    repos.sort(key=lambda r: (r["private"], r["repo"]))
    return repos


async def main() -> None:
    import psycopg
    from psycopg.types.json import Jsonb

    dsn = os.environ["DATABASE_URL"]
    _assert_local(dsn)
    requester = os.environ.get("DASHBOARD_DEV_PRINCIPAL", "ashrithaumd")
    now = datetime.now(timezone.utc)
    # Validate every row BEFORE touching the database.
    rows = [build_review_row(t) for t in review_templates()]

    async with await psycopg.AsyncConnection.connect(dsn) as conn:
        for stmt in _REMOVE:
            await conn.execute(stmt, {"legacy": LEGACY_FIXTURE_OWNER} if "%(legacy)s" in stmt else None)
        if "--remove" in sys.argv:
            await conn.commit()
            print("removed all sample reviews and audits")
            return

        repos = target_repos(requester)
        if not repos:
            sys.exit(f"no installed repos owned by {requester} found; nothing seeded")
        # Spread over up to three repos so the Repositories page shows varied
        # activity; a fourth+ repo stays "never reviewed".
        picks = repos[:3]
        # The multi-language PR (rows 6-7) goes on the first repo too.
        plan = {0: rows[0:4] + rows[6:8], 1: rows[4:5], 2: rows[5:6]}
        n_reviews = 0
        for idx, repo in enumerate(picks):
            for r in plan.get(idx, []):
                vc, gen, det, unv = r["buckets"]
                await conn.execute(_INSERT, (
                    sid("review", repo["repo"], r["pr"], r["action"], r["age"]),
                    repo["owner"], repo["repo"], r["pr"], sha(repo["repo"], r["pr"], r["age"]),
                    r["action"], repo["private"],
                    r["summary"], r["conclusion"], r["gate"], r["fix"],
                    r["files_seen"], r["files_reviewed"], r["findings_total"], vc, gen, det, unv,
                    r["dismissed_count"], r["inline_count"], r["fix_suggestion_count"], r["budget_exceeded"],
                    Jsonb(r["filtered"]), r["title"],
                    r["tokens"][0], r["tokens"][1], r["cost"], r["duration"],
                    Jsonb(r.get("latencies", [])), Jsonb(r["findings"]),
                    Jsonb(r["dismissed_json"]), Jsonb(r["fix_suggestions"]),
                    Jsonb(r.get("failures", [])), now - r["age"], r["dependency_check_unavailable"],
                ))
                n_reviews += 1

        # Audits: one finished, one failed, on public repos only (the only
        # kind the real button can audit). Terminal statuses, so they never
        # block a real Run audit via the in-flight indexes.
        public = [r for r in picks if not r["private"]]
        n_audits = 0
        if public:
            r = public[0]
            await conn.execute(
                """INSERT INTO audits (id, owner, repo, requested_by, private, status,
                       report_markdown, report_json, exit_code, tokens_in, tokens_out,
                       estimated_cost_usd, duration_s, created_at, started_at, finished_at)
                   VALUES (%s,%s,%s,%s,false,'done',%s,%s,0,%s,%s,%s,%s,%s,%s,%s)""",
                (sid("audit", r["repo"], "done"), r["owner"], r["repo"], requester,
                 sample_audit_markdown(r["owner"], r["repo"]),
                 Jsonb(sample_audit_report_json(r["owner"], r["repo"])),
                 24_310, 3_105, 0.2140, 142.6, now - timedelta(days=1, minutes=3),
                 now - timedelta(days=1, minutes=3), now - timedelta(days=1)),
            )
            n_audits += 1
            # Multi-language: one with OSV unreachable (older), one with the
            # dependency findings (newest, so it is the repo's latest audit).
            for unavailable, age in ((True, timedelta(hours=12)), (False, timedelta(hours=2))):
                md, data = multilanguage_audit(r["owner"], r["repo"], osv_unavailable=unavailable)
                await conn.execute(
                    """INSERT INTO audits (id, owner, repo, requested_by, private, status,
                           report_markdown, report_json, exit_code, tokens_in, tokens_out,
                           estimated_cost_usd, duration_s, created_at, started_at, finished_at)
                       VALUES (%s,%s,%s,%s,false,'done',%s,%s,0,%s,%s,%s,%s,%s,%s,%s)""",
                    (sid("audit", r["repo"], "multilanguage", unavailable), r["owner"], r["repo"], requester,
                     md, Jsonb(data), 21_870, 3_340, 0.1532, 118.4, now - age - timedelta(minutes=2),
                     now - age - timedelta(minutes=2), now - age),
                )
                n_audits += 1
        if len(public) > 1:
            r = public[1]
            await conn.execute(
                """INSERT INTO audits (id, owner, repo, requested_by, private, status, error,
                       exit_code, duration_s, created_at, started_at, finished_at)
                   VALUES (%s,%s,%s,%s,false,'failed',%s,2,%s,%s,%s,%s)""",
                (sid("audit", r["repo"], "failed"), r["owner"], r["repo"], requester,
                 "SAMPLE DATA - not a real audit. git clone failed: remote end hung up unexpectedly",
                 8.4, now - timedelta(hours=5), now - timedelta(hours=5),
                 now - timedelta(hours=5) + timedelta(seconds=8)),
            )
            n_audits += 1
        await conn.commit()
    print(f"seeded {n_reviews} sample reviews and {n_audits} sample audits on: "
          + ", ".join(f"{r['owner']}/{r['repo']}{' (private)' if r['private'] else ''}" for r in picks))


if __name__ == "__main__":
    asyncio.run(main())
