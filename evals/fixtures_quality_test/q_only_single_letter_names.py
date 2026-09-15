"""Quality issue only: single-letter/meaningless names on an otherwise
trivial, single-expression function — nothing here is complex or
branchy enough for the test-coverage agent to reasonably flag."""


def c(p, d):
    return p - (p * d / 100)
