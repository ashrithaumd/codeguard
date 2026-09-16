"""A genuine hardcoded credential — Bandit's B105 should fire, and
review_security should confirm it: there's no mitigating context here,
the password really is baked into the source."""


def connect_to_db():
    password = "SuperSecret123!"
    return _open_connection(user="admin", password=password)


def _open_connection(user, password):
    raise NotImplementedError
