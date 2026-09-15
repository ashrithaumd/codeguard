"""CI enforcement of evals/adversarial/run_adversarial_eval.py — a
regression fails the build here, not just the standalone script's own
printed report. See that module's docstring for what these vectors
prove and don't prove; no live API calls anywhere in this file.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2] / "evals" / "adversarial"))

from run_adversarial_eval import (  # noqa: E402
    EXPECTED_DETECTED_ATTEMPTS,
    FILE_VECTORS,
    check_codeguard_yml_isolation,
    check_file_vector,
    check_pr_metadata_not_wired,
)


def test_every_recognizable_injection_attempt_is_counted():
    for name in FILE_VECTORS:
        result = check_file_vector(name)
        assert result.attempts_detected == EXPECTED_DETECTED_ATTEMPTS, (
            f"{name}: expected {EXPECTED_DETECTED_ATTEMPTS} recognizable attempts neutralized, "
            f"got {result.attempts_detected}"
        )


def test_no_recognizable_injection_phrase_reaches_the_model_prompt():
    for name in FILE_VECTORS:
        result = check_file_vector(name)
        assert not result.prompt_leaked_raw_injection, f"{name}: raw injection phrase reached the model prompt"


def test_review_output_is_identical_with_and_without_the_injection():
    """The done-when criterion: for a model that behaves the same
    regardless of input (canned response — see check_file_vector), the
    pipeline's own structured output must diff clean between the
    injected fixture and its clean counterpart."""
    for name in FILE_VECTORS:
        result = check_file_vector(name)
        assert not result.findings_diff, f"{name}: review output diverged between clean and injected fixture"


def test_codeguard_yml_is_never_read_from_the_pr_head():
    result = check_codeguard_yml_isolation()

    assert result.fetched_refs == ["main"]
    assert result.ok


def test_pr_title_description_commit_message_never_reach_a_prompt():
    assert check_pr_metadata_not_wired()
