"""Parses a GitHub patch's hunk headers and expands each hunk to ~30
lines of surrounding context using the file's full content at head_sha
— GitHub's `patch` field only carries ~3 lines of context by default,
with no parameter to request more, so getting real context means
re-deriving hunk boundaries from the patch and slicing the actual file.
"""

from __future__ import annotations

import hashlib
import re

from codeguard.diff.models import Hunk

CONTEXT_LINES = 30

_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def hash_content(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def parse_hunk_ranges(patch: str) -> list[tuple[int, int]]:
    """Returns (new_file_start, new_file_count) for each @@ header in
    the patch, 1-indexed per unified diff convention. count omitted in
    the header means 1.
    """
    ranges = []
    for line in patch.splitlines():
        m = _HUNK_HEADER_RE.match(line)
        if m:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            ranges.append((start, count))
    return ranges


def expand_and_merge_ranges(ranges: list[tuple[int, int]], total_lines: int) -> list[tuple[int, int]]:
    """Each (start, count) -> (start - 30, start + count - 1 + 30),
    clamped to [1, total_lines], then merges overlapping/adjacent
    windows — a file with several nearby hunks shouldn't produce
    duplicate or overlapping context blocks.
    """
    expanded = []
    for start, count in ranges:
        lo = max(1, start - CONTEXT_LINES)
        hi = min(total_lines, start + max(count, 1) - 1 + CONTEXT_LINES)
        expanded.append((lo, hi))
    expanded.sort()

    merged: list[list[int]] = []
    for lo, hi in expanded:
        if merged and lo <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], hi)
        else:
            merged.append([lo, hi])
    return [(lo, hi) for lo, hi in merged]


def build_hunks(path: str, patch: str, full_content: str | None) -> list[Hunk]:
    """full_content=None (the file's content fetch failed) falls back
    to the patch's own ~3-line context rather than dropping the file
    from review entirely — degraded, not silently missing.
    """
    if full_content is None:
        return [Hunk(path=path, start_line=0, end_line=0, content=patch, content_hash=hash_content(patch))]

    lines = full_content.splitlines()
    ranges = parse_hunk_ranges(patch)
    if not ranges:
        return []

    merged = expand_and_merge_ranges(ranges, len(lines))
    hunks = []
    for lo, hi in merged:
        block = "\n".join(lines[lo - 1:hi])
        hunks.append(Hunk(path=path, start_line=lo, end_line=hi, content=block, content_hash=hash_content(block)))
    return hunks
