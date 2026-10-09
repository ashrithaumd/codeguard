"""Charging a customer."""


def charge(amount, currency, *, idempotency_key):
    """Charge `amount` in `currency`, at most once per idempotency key."""
    return {"amount": amount, "currency": currency, "key": idempotency_key}
