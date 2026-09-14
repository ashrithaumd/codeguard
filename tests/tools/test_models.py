from codeguard.severity import Severity
from codeguard.tools.models import Finding


def _finding(**overrides):
    defaults = dict(file="a.py", start_line=1, end_line=1, severity=Severity.HIGH,
                     source_tool="bandit", rule_id="B101", message="msg")
    defaults.update(overrides)
    return Finding.create(**defaults)


def test_fingerprint_is_deterministic_for_identical_inputs():
    assert _finding().fingerprint == _finding().fingerprint


def test_fingerprint_differs_when_line_differs():
    assert _finding(start_line=1).fingerprint != _finding(start_line=2).fingerprint


def test_fingerprint_differs_when_rule_differs():
    assert _finding(rule_id="B101").fingerprint != _finding(rule_id="B608").fingerprint
