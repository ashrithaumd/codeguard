"""A genuine eval() of user-controlled input — Bandit's B307 should
fire, and review_security should confirm it: expression comes straight
from an HTTP request body with no sanitization."""


def compute_from_request(request):
    expression = request.get("expression")
    return eval(expression)
