from enum import IntEnum


class Severity(IntEnum):
    """Ordered so `finding.severity >= threshold` works directly.

    Values are ints, not the strings a human would write in YAML
    ("high"). The .codeguard.yml loader (Phase 3) is responsible for
    case-insensitively parsing a string like "high" into Severity.HIGH —
    that parsing doesn't exist yet, deliberately (see config.py).
    """
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
