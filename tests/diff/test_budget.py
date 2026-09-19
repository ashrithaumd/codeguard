"""Exercises the budget-truncation path — not just budget_exceeded=False
against small PRs. apply_file_budget
and apply_token_budget were extracted as pure functions from ingest.py
specifically to make this possible without hitting the real GitHub API.
"""

from __future__ import annotations

from codeguard.config import Budget
from codeguard.diff.ingest import apply_file_budget, apply_token_budget
from codeguard.diff.models import Hunk


def _file(name, additions=5, deletions=0):
    return {"filename": name, "additions": additions, "deletions": deletions, "patch": "@@ -1,1 +1,1 @@\n+x"}


def test_apply_file_budget_keeps_everything_under_limit():
    files = [_file(f"f{i}.py") for i in range(3)]
    budget = Budget(max_files=5, max_tokens=1000, max_wall_clock_s=60)
    kept, filtered, exceeded = apply_file_budget(files, budget)
    assert len(kept) == 3
    assert filtered == []
    assert exceeded is False


def test_apply_file_budget_drops_excess_smallest_diffs_first():
    files = [_file(f"f{i}.py", additions=i + 1) for i in range(5)]  # f0=1 add ... f4=5 adds
    budget = Budget(max_files=2, max_tokens=1000, max_wall_clock_s=60)
    kept, filtered, exceeded = apply_file_budget(files, budget)
    assert exceeded is True
    assert {f["filename"] for f in kept} == {"f4.py", "f3.py"}
    assert {f.path for f in filtered} == {"f0.py", "f1.py", "f2.py"}
    assert all(f.reason == "dropped by max_files budget" for f in filtered)


def _hunk(path, content, start=1):
    return Hunk(path=path, start_line=start, end_line=start, content=content, content_hash="h")


def test_apply_token_budget_keeps_everything_under_limit():
    hunks = [_hunk("a.py", "small"), _hunk("b.py", "small too")]
    budget = Budget(max_files=10, max_tokens=1000, max_wall_clock_s=60)
    selected, filtered, exceeded = apply_token_budget(hunks, budget)
    assert len(selected) == 2
    assert filtered == []
    assert exceeded is False


def test_apply_token_budget_drops_lowest_priority_hunks_when_over_limit():
    # Distinct "wordN" tokens rather than a repeated pattern, so BPE
    # compression doesn't make the token count unpredictably small.
    big_content = " ".join(f"unique_token_{i}" for i in range(2000))
    main_hunk = Hunk(path="main.py", start_line=1, end_line=1, content=big_content, content_hash="h1")
    z_hunk = Hunk(path="z.py", start_line=1, end_line=1, content=big_content, content_hash="h2")
    budget = Budget(max_files=10, max_tokens=500, max_wall_clock_s=60)

    # z_hunk first in input order — priority sort inside the function
    # must still put main.py first (matches _hunk_priority) and keep it.
    selected, filtered, exceeded = apply_token_budget([z_hunk, main_hunk], budget)

    assert exceeded is True
    assert [h.path for h in selected] == ["main.py"]
    assert [f.path for f in filtered] == ["z.py"]
    assert filtered[0].reason == "dropped by max_tokens budget"


def test_apply_token_budget_always_keeps_at_least_one_hunk_even_if_it_alone_exceeds_budget():
    huge = " ".join(f"unique_token_{i}" for i in range(5000))
    hunk = _hunk("main.py", huge)
    budget = Budget(max_files=10, max_tokens=10, max_wall_clock_s=60)
    selected, filtered, exceeded = apply_token_budget([hunk], budget)
    assert len(selected) == 1  # never zero hunks just because the first one is big
    assert filtered == []
