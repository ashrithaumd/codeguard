from __future__ import annotations

from pydantic import BaseModel, Field


class Hunk(BaseModel):
    """One reviewable chunk of a file's diff, expanded to ~30 lines of
    surrounding context (GitHub's own patch only gives ~3). start_line/
    end_line are 1-indexed, inclusive, in the file at head_sha.
    content_hash exists now so later phases (repo decision: "on
    synchronize, hash each hunk; reuse stored findings for unchanged
    hunks") have something to key off of — the reuse logic itself isn't
    built yet, this just lays the groundwork.
    """
    path: str
    start_line: int
    end_line: int
    content: str
    content_hash: str


class FilteredFile(BaseModel):
    path: str
    reason: str


class DiffIngestionResult(BaseModel):
    owner: str
    repo: str
    pr_number: int
    files_seen: int
    files_filtered: list[FilteredFile] = Field(default_factory=list)
    hunks: list[Hunk] = Field(default_factory=list)
    budget_exceeded: bool = False

    @property
    def files_reviewed(self) -> list[str]:
        seen = []
        for h in self.hunks:
            if h.path not in seen:
                seen.append(h.path)
        return seen
