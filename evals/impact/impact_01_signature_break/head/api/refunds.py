"""Already passes an idempotency key, so the new signature is fine here."""

from billing import charge as billing_charge


def recharge(order):
    return billing_charge.charge(order["total"], order["currency"], idempotency_key=order["id"])
