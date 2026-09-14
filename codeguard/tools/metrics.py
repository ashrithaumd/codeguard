from prometheus_client import Counter, Histogram

tool_run_duration_seconds = Histogram(
    "codeguard_tools_run_duration_seconds",
    "Wall time for one tool run against one file.",
    ["tool"],
)
findings_total = Counter(
    "codeguard_tools_findings_total",
    "Findings produced, by tool and severity, after changed-line filtering.",
    ["tool", "severity"],
)
tool_failures_total = Counter(
    "codeguard_tools_failures_total",
    "Tool runs that crashed or timed out (produced an 'unavailable' finding instead of aborting).",
    ["tool"],
)
