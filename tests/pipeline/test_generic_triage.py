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
