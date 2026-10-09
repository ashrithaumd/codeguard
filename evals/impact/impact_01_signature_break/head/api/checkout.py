"""Checkout: the caller this PR breaks without touching it."""

from billing.charge import charge


def checkout(cart):
    total = sum(item["price"] for item in cart)
    return charge(total, "usd")
