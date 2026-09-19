from enum import IntEnum


class Severity(IntEnum):
    """Ordered so `finding.severity >= threshold` works directly.

    Values are ints, not the strings a human would write in YAML
    ("high"). The .codeguard.yml loader case-insensitively parses a
    string like "high" into Severity.HIGH — see config.py's own
    field validators.
    """
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
