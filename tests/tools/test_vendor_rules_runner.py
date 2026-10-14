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
    assert VENDOR_LANGUAGE_FILES == frozenset({"JavaScript", "TypeScript", "Go", "Java", "C#", "Dockerfile"})


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


# codeguard-go-math-rand-secret: plain `import "math/rand"` for a secret
# (the vendored weakrandsource rule matches only an aliased import).
RAND_RULE = "codeguard-go-math-rand-secret"
GO_TOKEN = ('package auth\n\nimport "{imp}"\n\n'
            'func NewSessionToken() []byte {{\n\tb := make([]byte, 32)\n\t{alias}.Read(b)\n\treturn b\n}}\n')


def test_math_rand_for_a_token_with_the_plain_import_is_found():
    findings = run_vendor_rules({"auth/token.go": GO_TOKEN.format(imp="math/rand", alias="rand")})
    assert [(f.rule_id, f.start_line, f.source_tool) for f in findings if f.rule_id == RAND_RULE] == [
        (RAND_RULE, 7, "codeguard-rules")]


def test_crypto_rand_for_a_token_is_left_alone():
    findings = run_vendor_rules({"auth/token.go": GO_TOKEN.format(imp="crypto/rand", alias="rand")})
    assert [f for f in findings if f.rule_id == RAND_RULE] == []


def test_an_aliased_import_is_covered_too_including_what_the_vendored_rule_skips():
    """Semgrep resolves Go import aliases, so `mrand "math/rand"` is ours as
    well -- including Read and Intn, which the vendored weakrandsource rule
    does not list."""
    src = GO_TOKEN.format(imp="math/rand", alias="mrand").replace('import "math/rand"', 'import mrand "math/rand"')
    findings = run_vendor_rules({"auth/token.go": src})
    assert [(f.rule_id, f.start_line) for f in findings if f.rule_id == RAND_RULE] == [(RAND_RULE, 7)]


# codeguard-java-runtime-exec-injection: the one-line Runtime.getRuntime().exec
# form the vendored CommandInjection rule (typed-variable sink) misses.
JAVA_PING = ('import java.io.IOException;\nimport javax.servlet.http.HttpServletRequest;\n\n'
             'public class Ping {{\n'
             '    public void ping(HttpServletRequest request) throws IOException {{\n'
             '        String host = request.getParameter("host");\n'
             '{call}\n    }}\n}}\n')
EXEC_RULE = "codeguard-java-runtime-exec-injection"


def test_the_one_line_exec_form_is_ours_and_the_variable_form_stays_vendored():
    direct = JAVA_PING.format(call='        Runtime.getRuntime().exec("ping -c 1 " + host);')
    via_var = JAVA_PING.format(call='        Runtime runtime = Runtime.getRuntime();\n'
                                    '        runtime.exec("ping -c 1 " + host);')
    findings = run_vendor_rules({"a/Direct.java": direct, "b/ViaVar.java": via_var})
    got = sorted((f.file, f.rule_id, f.source_tool) for f in findings)
    assert got == [("a/Direct.java", EXEC_RULE, "codeguard-rules"),
                   ("b/ViaVar.java", "java_inject_rule-CommandInjection", "gitlab-sast")]


def test_a_failed_run_is_named_apart_from_the_python_semgrep_run():
    from codeguard.tools.base import UNAVAILABLE_RULE_ID
    with patch("codeguard.tools.base.subprocess.run", side_effect=subprocess.TimeoutExpired("semgrep", 60)):
        [f] = run_vendor_rules({"a.js": "x = 1\n"})
    assert (f.rule_id, f.source_tool) == (UNAVAILABLE_RULE_ID, "semgrep-non-python")


# Dockerfiles: our own rules (rules_lang/dockerfile-security.yaml), same pass.
DOCKERFILE = "FROM node:latest\nRUN curl -fsSL https://get.example.com/i.sh | sh\nUSER node\n"


def test_a_dockerfile_is_scanned_by_our_rules_in_the_same_pass():
    findings = run_vendor_rules({"Dockerfile": DOCKERFILE})
    assert sorted((f.rule_id, f.start_line, f.source_tool) for f in findings) == [
        ("codeguard-dockerfile-curl-pipe-shell", 2, "codeguard-rules"),
        ("codeguard-dockerfile-latest-tag", 1, "codeguard-rules"),
    ]


def test_the_generic_scanners_are_the_semgrep_pass_plus_zizmor():
    from codeguard.tools.generic import run_generic_scanners
    files = {"a.js": "x\n", ".github/workflows/ci.yml": "on: push\n"}
    seen = {}

    def record(name):
        return lambda f: seen.setdefault(name, f) and []

    with patch("codeguard.tools.generic.run_vendor_rules", side_effect=record("semgrep")), \
         patch("codeguard.tools.generic.run_zizmor", side_effect=record("zizmor")):
        assert run_generic_scanners(files) == []
    assert seen == {"semgrep": files, "zizmor": files}
