"""Quality issue only: three copy-pasted blocks that only differ by a
literal status string — real duplication, but each block is a trivial,
unconditional assignment with no branching logic worth testing."""


def build_status_labels():
    labels = {}
    labels["pending"] = "Pending"
    labels["pending_display"] = "Pending".upper()
    labels["pending_short"] = "Pending"[:3]

    labels["active"] = "Active"
    labels["active_display"] = "Active".upper()
    labels["active_short"] = "Active"[:3]

    labels["closed"] = "Closed"
    labels["closed_display"] = "Closed".upper()
    labels["closed_short"] = "Closed"[:3]
    return labels
