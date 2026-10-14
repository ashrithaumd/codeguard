"""Enforces rules/llm-security.py, the Semgrep annotated test file for
rules/llm-security.yaml.

That file has always existed and has always passed, but nothing ever ran
it: `semgrep --test` appeared in no CI config, no pytest, and no
documentation, so a broken pattern would only have surfaced as a silent
loss of findings on a real review. This module is what makes a
pattern regression fail a build.

Two different checks, deliberately split because they fail for different
reasons and run in different places:

- test_semgrep_rule_tests_pass shells out to the real `semgrep --test`,
  so it needs the binary and skips on Windows, same as
  tests/tools/test_runners_live.py.
- test_every_rule_has_at_least_one_positive_test_case is pure parsing
  with no subprocess, so it runs everywhere including Windows. It
  catches the case `semgrep --test` cannot report on: a rule added to
  the YAML with no annotation in the test file at all has nothing to
  fail, and a "10/10 passed" line says nothing about the eleventh rule.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
RULES_YAML = RULES_DIR / "llm-security.yaml"
RULES_TESTS = RULES_DIR / "llm-security.py"

_SEMGREP_WINDOWS_SKIP = (
    "semgrep's native scanning engine isn't available under this Windows "
    "install — the same limitation tests/tools/test_runners_live.py skips "
    "around. The actual deployment target is Linux containers, where this "
    "runs for real."
)


def _declared_rule_ids() -> list[str]:
    spec = yaml.safe_load(RULES_YAML.read_text(encoding="utf-8"))
    return [rule["id"] for rule in spec["rules"]]


@pytest.mark.skipif(sys.platform == "win32", reason=_SEMGREP_WINDOWS_SKIP)
def test_semgrep_rule_tests_pass():
    """`semgrep --test` exits 0 when every `# ruleid:` line is matched
    and every `# ok:` line is not; it exits 1 and names the rule plus
    its missed/incorrect lines otherwise. The full output is attached to
    the assertion because that message is the entire diagnostic — which
    pattern broke, and where.
    """
    proc = subprocess.run(
        ["semgrep", "--test", "--metrics=off", "--jobs", "1", "--max-memory", "1024", str(RULES_DIR)],
        capture_output=True, text=True, timeout=300,
    )

    assert proc.returncode == 0, f"semgrep --test failed:\n{proc.stdout}\n{proc.stderr}"


def test_every_rule_has_at_least_one_positive_test_case():
    """A rule with no `# ruleid:` annotation is untested, and
    `semgrep --test` will not say so — it only reports on rules that
    have cases. Without this, adding a rule and forgetting its test
    still prints "All tests passed".
    """
    annotated = set(re.findall(r"#\s*ruleid:\s*([\w-]+)", RULES_TESTS.read_text(encoding="utf-8")))

    missing = [rule_id for rule_id in _declared_rule_ids() if rule_id not in annotated]

    assert not missing, (
        f"{len(missing)} rule(s) in llm-security.yaml have no '# ruleid:' case "
        f"in llm-security.py: {missing}"
    )


def test_no_test_case_references_an_unknown_rule():
    """The reverse drift: an annotation left behind after a rule was
    renamed or removed silently stops testing anything, since
    `semgrep --test` has no rule to match it against.
    """
    declared = set(_declared_rule_ids())
    content = RULES_TESTS.read_text(encoding="utf-8")
    annotated = set(re.findall(r"#\s*(?:ruleid|ok|todoruleid|todook):\s*([\w-]+)", content))

    unknown = sorted(annotated - declared)

    assert not unknown, f"llm-security.py references rule id(s) not in llm-security.yaml: {unknown}"


# rules_lang/: CodeGuard's own rules for the non-Python languages (NOTICE).
LANG_RULES_DIR = RULES_DIR.parent / "rules_lang"


@pytest.mark.skipif(sys.platform == "win32", reason=_SEMGREP_WINDOWS_SKIP)
def test_own_language_rule_tests_pass():
    proc = subprocess.run(
        ["semgrep", "--test", "--metrics=off", "--jobs", "1", "--max-memory", "1024", str(LANG_RULES_DIR)],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"semgrep --test failed:\n{proc.stdout}\n{proc.stderr}"


def test_every_own_language_rule_has_a_positive_and_a_near_miss_case():
    for rules_yaml in sorted(LANG_RULES_DIR.glob("*.yaml")):
        cases = "".join(p.read_text(encoding="utf-8") for p in LANG_RULES_DIR.glob(rules_yaml.stem + ".*")
                        if p.suffix != ".yaml")
        for rule in yaml.safe_load(rules_yaml.read_text(encoding="utf-8"))["rules"]:
            assert re.search(rf"ruleid:\s*{re.escape(rule['id'])}\b", cases), rule["id"]
            assert re.search(rf"ok:\s*{re.escape(rule['id'])}\b", cases), rule["id"]


@pytest.mark.skipif(sys.platform == "win32", reason=_SEMGREP_WINDOWS_SKIP)
@pytest.mark.parametrize("case", ["js-llm-security.ts", "js-llm-security.js"])
def test_each_js_llm_case_file_is_tested(case):
    """`semgrep --test` over the directory picks its own case file per rule
    file; the TypeScript and the CommonJS JavaScript cases are each run
    explicitly so neither can silently drop out."""
    proc = subprocess.run(
        ["semgrep", "--test", "--metrics=off", "--jobs", "1", "--max-memory", "1024",
         "--config", str(LANG_RULES_DIR / "js-llm-security.yaml"), str(LANG_RULES_DIR / case)],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"semgrep --test failed:\n{proc.stdout}\n{proc.stderr}"
    assert "All tests passed" in proc.stdout + proc.stderr
    assert "No unit tests found" not in proc.stdout + proc.stderr
