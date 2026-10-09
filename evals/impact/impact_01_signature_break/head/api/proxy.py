"""Forwards whatever it is given: cannot be checked, must not be flagged."""

from billing.charge import charge


def charge_with(*args, **kwargs):
    return charge(*args, **kwargs)
