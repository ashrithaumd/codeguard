from prometheus_client import Counter

files_seen_total = Counter(
    "codeguard_diff_files_seen_total",
    "Files seen in a PR diff, before any filtering.",
)
files_filtered_total = Counter(
    "codeguard_diff_files_filtered_total",
    "Files filtered out of review, by reason.",
    ["reason"],
)
files_reviewed_total = Counter(
    "codeguard_diff_files_reviewed_total",
    "Files that passed filtering and budget and produced at least one hunk.",
)
budget_exceeded_total = Counter(
    "codeguard_diff_budget_exceeded_total",
    "PRs where budget enforcement (max_files or max_tokens) dropped otherwise-reviewable content.",
)
