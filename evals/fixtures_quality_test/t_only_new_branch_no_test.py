"""Test-coverage issue only: well-named, readable function that adds a
real edge-case branch (zero/negative quantity) with no accompanying
test evident anywhere in view — nothing here is a naming, complexity,
or duplication problem."""


def calculate_unit_price(total_cost, quantity):
    if quantity <= 0:
        return 0.0
    return total_cost / quantity
