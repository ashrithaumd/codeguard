def calculate_total(items):
    """Sums the price field of each item."""
    return sum(i["price"] for i in items)
