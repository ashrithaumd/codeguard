"""The vendored GitLab rules, run on the languages they cover.

source_tool "gitlab-sast", not "semgrep": the Python pipeline routes on
source_tool ("semgrep" -> the AI-aware agent, "bandit" -> security), so a
distinct name means nothing in the Python path can ever claim these. Only
JS/TS, Go, Java and C# files are handed to it; a Python file never is.
Offline, like every Semgrep run (the runner's own environment).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from codeguard.tools.semgrep_runner import VENDOR_LANGUAGE_FILES, run_vendor_rules

JS_EVAL = "function run(userInput) {\n  return eval(userInput);\n}\n"
GO_SQL = ('package main\n\nimport (\n\t"database/sql"\n\t"fmt"\n)\n\n'
          'func find(db *sql.DB, name string) {\n'
          '\tdb.Query(fmt.Sprintf("SELECT * FROM users WHERE name = \'%s\'", name))\n}\n')


def test_planted_bugs_in_js_and_go_are_found_with_a_distinct_source_tool():
    findings = run_vendor_rules({"web/run.js": JS_EVAL, "cmd/find.go": GO_SQL})
    by_file = {}
    for f in findings:
        by_file.setdefault(f.file, set()).add(f.rule_id)
    assert any("eval" in r for r in by_file.get("web/run.js", ())), by_file
    assert any("sql" in r.lower() for r in by_file.get("cmd/find.go", ())), by_file
    assert {f.source_tool for f in findings} == {"gitlab-sast"}
    assert all("." not in f.rule_id for f in findings)  # the rule's own id, not the config path


def test_python_and_other_files_are_never_handed_to_the_vendored_rules():
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout='{"results": [], "errors": []}', stderr="")

    with patch("codeguard.tools.base.subprocess.run", side_effect=fake_run):
        run_vendor_rules({"app.py": "x = 1\n", "a.rb": "x = 1\n", "notes.md": "#\n"})
    assert calls == []  # nothing in scope, so Semgrep is not even started


def test_the_scope_is_exactly_the_covered_languages():
    assert VENDOR_LANGUAGE_FILES == frozenset({"JavaScript", "TypeScript", "Go", "Java", "C#"})


def test_it_runs_offline_like_every_semgrep_call():
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(kwargs.get("env") or {})
        return subprocess.CompletedProcess(cmd, 0, stdout='{"results": [], "errors": []}', stderr="")

    with patch("codeguard.tools.base.subprocess.run", side_effect=fake_run):
        run_vendor_rules({"a.js": "x = 1\n"})
    assert calls and calls[0]["SEMGREP_ENABLE_VERSION_CHECK"] == "0" and calls[0]["SEMGREP_SEND_METRICS"] == "off"


# --------------------------------------------------------------------------
# Our own Go rule (rules_lang/, see NOTICE), run alongside the vendored pack
# --------------------------------------------------------------------------

GO_TLS_OFF = ('package client\n\nimport (\n\t"crypto/tls"\n\t"net/http"\n)\n\n'
              'func New() *http.Client {\n'
              '\ttr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n'
              '\treturn &http.Client{Transport: tr}\n}\n')
GO_TLS_ON = GO_TLS_OFF.replace("InsecureSkipVerify: true", "InsecureSkipVerify: false")
OUR_RULE = "codeguard-go-tls-insecure-skip-verify"


def test_our_go_rule_finds_certificate_verification_turned_off():
    findings = run_vendor_rules({"client/http.go": GO_TLS_OFF})
    hits = [f for f in findings if f.rule_id == OUR_RULE]
    assert [(f.file, f.start_line) for f in hits] == [("client/http.go", 9)]
    assert hits[0].source_tool == "codeguard-rules"  # ours, named apart from the vendored pack


def test_our_go_rule_leaves_false_and_test_files_alone():
    findings = run_vendor_rules({"client/http.go": GO_TLS_ON, "client/http_test.go": GO_TLS_OFF})
    assert [f for f in findings if f.rule_id == OUR_RULE] == []


def test_our_rules_are_kept_apart_from_the_vendored_pack():
    from codeguard.tools.semgrep_runner import OWN_LANG_RULES_DIR, VENDOR_RULES_DIR
    assert OWN_LANG_RULES_DIR.name == "rules_lang" and OWN_LANG_RULES_DIR.is_dir()
    assert not (VENDOR_RULES_DIR / "go" / "go-insecure-skip-verify.yaml").exists()


def test_one_run_names_each_finding_by_where_its_rule_came_from():
    findings = run_vendor_rules({"web/run.js": JS_EVAL, "client/http.go": GO_TLS_OFF})
    tools = {f.rule_id: f.source_tool for f in findings}
    assert tools["javascript_eval_rule-eval-with-expression"] == "gitlab-sast"
    assert tools[OUR_RULE] == "codeguard-rules"


def test_every_own_rule_id_carries_the_prefix_the_runner_names_it_by():
    import yaml
    from codeguard.tools.semgrep_runner import OWN_LANG_RULES_DIR, OWN_RULE_PREFIX
    ids = [r["id"] for y in OWN_LANG_RULES_DIR.glob("*.yaml")
           for r in yaml.safe_load(y.read_text(encoding="utf-8"))["rules"]]
    assert ids and all(i.startswith(OWN_RULE_PREFIX) for i in ids)
    vendored = Path(__file__).resolve().parents[2] / "rules_vendor" / "gitlab-sast-rules"
    assert not any(OWN_RULE_PREFIX in y.read_text(encoding="utf-8") for y in vendored.rglob("*.yml"))


def test_our_findings_take_the_same_generic_review_path():
    """Triage routes by file, not by tool: a codeguard-rules finding of
    MEDIUM or above goes to the model exactly like a gitlab-sast one."""
    from codeguard.pipeline.generic_review import triage
    findings = run_vendor_rules({"client/http.go": GO_TLS_OFF})
    t = triage(findings, {"client/http.go": GO_TLS_OFF}, max_files=10, max_findings_per_file=30)
    assert [f.rule_id for f in t.to_model["client/http.go"]] == [OUR_RULE]
