"""Credential dismissals group by rule_id + shape class, not exact reason.

A shape-based reason names each value's length ("42-char sk-style token,
placeholder-like"), so four placeholder keys on codeguard-playground were
four different reasons and three rows. They share a rule and a shape class,
which is what the dismissal rests on: one row, with each line's length
listed inside it. Reasons of any other form still group by exact text.
"""

from __future__ import annotations

from codeguard.api.display import group_dismissed
from codeguard.pipeline.models import DismissedFinding
from codeguard.pipeline.nodes import _group_dismissed
from codeguard.redact import grouped_shape_reason, parse_shape_reason, shape_reason

RULE = "llm-hardcoded-api-key"


def _reason(desc: str, kind: str = "placeholder-like") -> str:
    return shape_reason([f"{desc}, {kind}"])


PLAYGROUND = [
    (21, _reason("42-char sk-style token")),
    (24, _reason("42-char sk-style token")),
    (25, _reason("43-char token")),
    (45, _reason("37-char token")),
]


def test_the_reason_text_is_unchanged_for_a_single_dismissal():
    assert _reason("42-char sk-style token") == (
        "Dismissed on the value's shape alone: 42-char sk-style token, placeholder-like. Not a usable credential.")


def test_parse_shape_reason():
    assert parse_shape_reason(_reason("42-char sk-style token")) == ("placeholder-like", ["42-char sk-style token"])
    assert parse_shape_reason(shape_reason(["40-char token, placeholder-like", "12-char token, placeholder-like"])) == (
        "placeholder-like", ["40-char token", "12-char token"])
    assert parse_shape_reason(shape_reason(["40-char token, placeholder-like", "12-char token, high-entropy"])) is None
    assert parse_shape_reason("Simulation delays only.") is None


def test_the_grouped_reason_lists_each_length_with_its_lines():
    text = grouped_shape_reason("placeholder-like", [
        ("21", "42-char sk-style token"), ("24", "42-char sk-style token"),
        ("25", "43-char token"), ("45", "37-char token")])
    assert text == ("Dismissed on the value's shape alone, placeholder-like: 42-char sk-style token at 21, 24; "
                    "43-char token at 25; 37-char token at 45. Not a usable credential.")


# --------------------------------------------------------------------------
# The audit page (display.group_dismissed)
# --------------------------------------------------------------------------

def _audit_rows(items, file="assistant.py", rule=RULE):
    return group_dismissed([{"file": file, "start_line": n, "rule_id": rule, "reason": r} for n, r in items])


def test_the_four_playground_keys_are_one_row():
    [row] = _audit_rows(PLAYGROUND)
    assert row["locations"] == "assistant.py:21, 24, 25, 45" and row["count"] == 4
    assert row["reason"] == ("Dismissed on the value's shape alone, placeholder-like: 42-char sk-style token at "
                             "21, 24; 43-char token at 25; 37-char token at 45. Not a usable credential.")


def test_across_files_the_lines_inside_the_row_name_their_file():
    rows = group_dismissed([
        {"file": "a.py", "start_line": 3, "rule_id": RULE, "reason": _reason("40-char token")},
        {"file": "b.py", "start_line": 9, "rule_id": RULE, "reason": _reason("12-char token")},
    ])
    [row] = rows
    assert row["locations"] == "a.py:3, b.py:9"
    assert "40-char token at a.py:3; 12-char token at b.py:9" in row["reason"]


def test_different_rules_or_shape_classes_stay_apart():
    rows = group_dismissed([
        {"file": "a.py", "start_line": 1, "rule_id": RULE, "reason": _reason("40-char token")},
        {"file": "a.py", "start_line": 2, "rule_id": "B105", "reason": _reason("40-char token")},
        {"file": "a.py", "start_line": 3, "rule_id": RULE, "reason": _reason("40-char token", "low-entropy")},
    ])
    assert len(rows) == 3


def test_other_reasons_still_group_by_exact_text():
    rows = _audit_rows([(98, "Simulation delays only."), (103, "Simulation delays only."), (36, "Jitter.")],
                       file="worker/main.py", rule="B311")
    assert [(r["locations"], r["reason"]) for r in rows] == [
        ("worker/main.py:98, 103", "Simulation delays only."), ("worker/main.py:36", "Jitter.")]


def test_a_shape_group_keeps_its_place_in_the_list():
    rows = group_dismissed([
        {"file": "w.py", "start_line": 1, "rule_id": "B311", "reason": "Jitter."},
        *({"file": "assistant.py", "start_line": n, "rule_id": RULE, "reason": r} for n, r in PLAYGROUND),
        {"file": "w.py", "start_line": 2, "rule_id": "B311", "reason": "Jitter."},
    ])
    assert [r["rule_id"] for r in rows] == ["B311", RULE]


# --------------------------------------------------------------------------
# The PR review summary (nodes._group_dismissed)
# --------------------------------------------------------------------------

def test_the_pr_summary_groups_the_same_way():
    dismissed = [DismissedFinding(file="assistant.py", start_line=n, rule_id=RULE, reason=r) for n, r in PLAYGROUND]
    [(file, rule_id, reason, lines)] = _group_dismissed(dismissed)
    assert (file, rule_id, lines) == ("assistant.py", RULE, [21, 24, 25, 45])
    assert "42-char sk-style token at 21, 24; 43-char token at 25; 37-char token at 45" in reason
