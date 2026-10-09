"""Charging a customer."""


def charge(amount, currency):
    """Charge `amount` in `currency`. Returns the charge record."""
    return {"amount": amount, "currency": currency}
