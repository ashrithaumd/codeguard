"""Same bug, two rules, one finding -- for the new languages, via the merge
that already joins B307 and llm-output-to-dangerous-sink (pipeline/merge.py).
Our own rules overlap a vendored one in two places; each pair is one defect
at one sink, so it is reported once, listing both rule ids."""

from __future__ import annotations

from codeguard.pipeline import merge
from codeguard.pipeline.merge import merge_same_bug, rule_label
from codeguard.severity import Severity
from codeguard.tools.models import Finding


def _f(rule_id, tool="security_generic", file="auth/keys.go", line=6, severity=Severity.MEDIUM, **kw):
    return Finding.create(file=file, start_line=line, end_line=line, severity=severity,
                          source_tool=tool, rule_id=rule_id, message="m", **kw)


def test_the_math_rand_pair_merges_into_one_finding_with_both_rules():
    merged = merge_same_bug([_f("go_crypto_rule-weakrandsource"),
                             _f("codeguard-go-math-rand-secret", what="apiKey comes from math/rand.")])
    assert len(merged) == 1
    assert set(merged[0].sources) == {"go_crypto_rule-weakrandsource", "codeguard-go-math-rand-secret"}
    assert "codeguard-go-math-rand-secret" in rule_label(merged[0])


def test_the_math_rand_pair_merges_on_what_the_scanners_really_raise():
    """The overlap is real: an aliased import, Int63, into a key."""
    from codeguard.tools.semgrep_runner import run_vendor_rules
    src = 'package auth\n\nimport mrand "math/rand"\n\nfunc issue() int64 {\n\tapiKey := mrand.Int63()\n\treturn apiKey\n}\n'
    raw = run_vendor_rules({"auth/keys.go": src})
    assert len(raw) == 2
    merged = merge_same_bug(raw)
    assert len(merged) == 1 and len(merged[0].sources) == 2


def test_the_runtime_exec_pair_merges_into_one_finding_with_both_rules():
    merged = merge_same_bug([
        _f("java_inject_rule-CommandInjection", file="Ping.java", line=8, severity=Severity.HIGH),
        _f("codeguard-java-runtime-exec-injection", file="Ping.java", line=8, severity=Severity.CRITICAL),
    ])
    assert len(merged) == 1
    assert set(merged[0].sources) == {"java_inject_rule-CommandInjection", "codeguard-java-runtime-exec-injection"}
    assert merged[0].severity == Severity.CRITICAL


def test_the_pairs_merge_only_on_the_same_line():
    merged = merge_same_bug([_f("go_crypto_rule-weakrandsource", line=6),
                             _f("codeguard-go-math-rand-secret", line=9)])
    assert len(merged) == 2


def test_the_python_groups_are_exactly_what_they_were():
    assert merge._EQUIVALENT[:3] == (
        frozenset({"B307", "B102", "B602", "B605", "llm-output-to-dangerous-sink"}),
        frozenset({"B608", "llm-output-to-sql"}),
        frozenset({"B105", "B106", "B107", "llm-hardcoded-api-key", "llm-langchain-hardcoded-api-key"}),
    )
