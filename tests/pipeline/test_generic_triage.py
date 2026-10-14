"""Noise and cost control for the vendored-rule findings, before any model.

  LOW                         listed as found, no model
  hardcoded-credential rules  the shape classifier decides, no model:
                              placeholder-like is dropped and counted,
                              anything else is HIGH
  MEDIUM and up               one verdict call per FILE, at most
                              max_files files (most severe first), at most
                              max_findings_per_file per file
  beyond either cap           listed, marked unreviewed, and the file named
                              with the reason -- never silently dropped
"""

from __future__ import annotations

import random
import string

from codeguard.pipeline.generic_review import GENERIC_CREDENTIAL_RULES, triage
from codeguard.severity import Severity
from codeguard.tools.models import Finding


def _f(file, line, sev, rule="javascript_eval_rule-eval-with-expression"):
    return Finding.create(file=file, start_line=line, end_line=line, severity=sev, source_tool="gitlab-sast",
                          rule_id=rule, message=f"{rule} at {file}")


def _key(seed):
    rng = random.Random(seed)
    return "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(24))


def test_low_findings_are_listed_without_a_model():
    t = triage([_f("a.js", 1, Severity.LOW)], {"a.js": "x\n"}, max_files=10, max_findings_per_file=30)
    assert [f.file for f in t.passthrough] == ["a.js"] and t.to_model == {}


def test_medium_and_up_go_to_the_model_one_batch_per_file():
    findings = [_f("a.js", 1, Severity.MEDIUM), _f("a.js", 5, Severity.HIGH), _f("b.go", 2, Severity.MEDIUM)]
    t = triage(findings, {"a.js": "x\n", "b.go": "x\n"}, max_files=10, max_findings_per_file=30)
    assert {p: len(fs) for p, fs in t.to_model.items()} == {"a.js": 2, "b.go": 1}
    assert t.passthrough == [] and t.unreviewed == [] and t.capped_files == []


def test_the_file_cap_keeps_the_most_severe_files_and_names_the_rest():
    findings = ([_f(f"m{i}.js", 1, Severity.MEDIUM) for i in range(4)]
                + [_f("h.js", 1, Severity.HIGH), _f("c.js", 1, Severity.CRITICAL)])
    t = triage(findings, {f.file: "x\n" for f in findings}, max_files=3, max_findings_per_file=30)
    assert list(t.to_model) == ["c.js", "h.js", "m0.js"]
    assert sorted(f.file for f in t.unreviewed) == ["m1.js", "m2.js", "m3.js"]
    assert all(f.unreviewed for f in t.unreviewed)
    assert t.capped_files == [(p, "not reviewed by AI (cap: 3 files)") for p in ("m1.js", "m2.js", "m3.js")]


def test_the_per_file_cap_keeps_the_most_severe_findings():
    findings = [_f("a.js", i, Severity.MEDIUM) for i in range(1, 5)] + [_f("a.js", 9, Severity.HIGH)]
    t = triage(findings, {"a.js": "x\n" * 10}, max_files=10, max_findings_per_file=2)
    assert [(f.start_line, f.severity) for f in t.to_model["a.js"]] == [(9, Severity.HIGH), (1, Severity.MEDIUM)]
    assert sorted(f.start_line for f in t.unreviewed) == [2, 3, 4]
    assert t.capped_files == [("a.js", "3 finding(s) not reviewed by AI (cap: 2 per file)")]


def test_a_hardcoded_password_is_decided_by_its_shape_with_no_model():
    key = _key(1)
    content = f'class Db {{\n  String password = "{key}";\n  String passwordBackup = "changeme-placeholder-example";\n}}\n'
    rule = "java_password_rule-HardcodePassword"
    assert rule in GENERIC_CREDENTIAL_RULES
    t = triage([_f("Db.java", 2, Severity.MEDIUM, rule), _f("Db.java", 3, Severity.MEDIUM, rule)],
               {"Db.java": content}, max_files=10, max_findings_per_file=30)
    assert t.to_model == {}
    [real] = t.passthrough
    assert real.start_line == 2 and real.severity == Severity.HIGH
    assert key not in real.message + real.title + real.what
    assert t.placeholders == 1


def test_nothing_in_means_nothing_out():
    t = triage([], {}, max_files=10, max_findings_per_file=30)
    assert (t.to_model, t.passthrough, t.unreviewed, t.capped_files, t.placeholders) == ({}, [], [], [], 0)


# The credential line itself never reaches the model, even when the file goes
# to it for another finding: the vendored credential rules flag positional
# literals (getConnection(url, "admin", "hunter22")) that redact_source's
# assignment pattern cannot see.

def test_a_credential_finding_line_is_recorded_for_masking_placeholder_or_not():
    content = 'class A {\n  void a() { java.sql.DriverManager.getConnection(u, "admin", "hunter22"); }\n}\n'
    t = triage([_f("A.java", 2, Severity.MEDIUM, rule="java_password_rule-ConstantDBPassword"),
                _f("A.java", 3, Severity.MEDIUM)], {"A.java": content}, max_files=10, max_findings_per_file=30)
    assert t.masked_lines == {"A.java": {2}}
    assert "A.java" in t.to_model


def test_content_for_the_model_masks_secret_spans_and_credential_lines():
    from codeguard.pipeline.generic_review import content_for_model
    content = 'line one\n    getConnection(u, "admin", "hunter22");\nx = "abcdef";\n'
    t = triage([_f("A.java", 2, Severity.MEDIUM, rule="java_password_rule-ConstantDBPassword")],
               {"A.java": content}, max_files=10, max_findings_per_file=30)
    sent = content_for_model("A.java", content, [(3, 5, 11)], t)
    assert "hunter22" not in sent and "abcdef" not in sent
    assert sent.splitlines()[0] == "line one" and sent.splitlines()[1].startswith("    [redacted")
    assert sent.count("\n") == content.count("\n")


def test_a_scanner_that_did_not_run_is_named_never_reported_as_a_finding():
    from codeguard.tools.base import unavailable_finding
    t = triage([unavailable_finding("semgrep-non-python", "timed out after 60s"),
                _f("a.js", 2, Severity.MEDIUM)], {"a.js": "x\ny\n"}, max_files=10, max_findings_per_file=30)
    assert t.unavailable == ["semgrep-non-python"]
    assert all(f.file != "<pr>" for f in t.passthrough + t.unreviewed + sum(t.to_model.values(), []))


# codeguard-dockerfile-secret-in-env: a credential rule like Java's -- decided
# by the value's shape, its line masked, never sent to the model.
DOCKER_SECRET = "codeguard-dockerfile-secret-in-env"


def test_a_dockerfile_env_secret_is_decided_by_shape_and_never_sent():
    key = _key(9)
    content = f"FROM python:3.12-slim\nENV DB_PASSWORD={key}\nRUN curl -fsSL https://x.example/i.sh | sh\n"
    t = triage([_f("Dockerfile", 2, Severity.HIGH, rule=DOCKER_SECRET),
                _f("Dockerfile", 3, Severity.HIGH, rule="codeguard-dockerfile-curl-pipe-shell")],
               {"Dockerfile": content}, max_files=10, max_findings_per_file=30)
    [reported] = [f for f in t.passthrough if f.rule_id == DOCKER_SECRET]
    assert reported.severity == Severity.HIGH and key not in reported.message
    assert [f.rule_id for f in t.to_model["Dockerfile"]] == ["codeguard-dockerfile-curl-pipe-shell"]
    assert t.masked_lines == {"Dockerfile": {2}}


def test_a_placeholder_in_a_dockerfile_env_is_counted_not_reported():
    content = "FROM python:3.12-slim\nENV DB_PASSWORD=changeme\n"
    t = triage([_f("Dockerfile", 2, Severity.HIGH, rule=DOCKER_SECRET)], {"Dockerfile": content},
               max_files=10, max_findings_per_file=30)
    assert t.passthrough == [] and t.placeholders == 1


def test_dockerfile_values_are_read_quoted_or_not_with_either_syntax():
    from codeguard.pipeline.generic_review import dockerfile_assigned_value
    assert dockerfile_assigned_value("ENV DB_PASSWORD=hunter22") == "hunter22"
    assert dockerfile_assigned_value('ENV DB_PASSWORD="hunter 22"') == "hunter 22"
    assert dockerfile_assigned_value("ARG API_TOKEN abc123") == "abc123"
    assert dockerfile_assigned_value("ARG API_TOKEN") is None
