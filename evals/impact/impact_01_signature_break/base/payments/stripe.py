"""A different charge() with the old two-argument shape."""


def charge(amount, currency):
    return ("stripe", amount, currency)


def pay(total):
    return charge(total, "usd")
