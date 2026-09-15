"""Syntactically identical to a real hardcoded-password finding (Bandit's
B105 will fire on the literal), but this is a test file using an
obviously-fake placeholder credential to exercise an auth code path —
not a real secret. A context-aware reviewer should dismiss this."""


def test_login_rejects_wrong_password():
    password = "not-a-real-password-testing-only"
    assert authenticate(user="test_user", password=password) is False


def authenticate(user, password):
    raise NotImplementedError
