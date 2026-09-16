"""Syntactically identical to a real hardcoded-password finding (Bandit's
B105 will fire on the literal), but this is a test file using an
obviously-fake placeholder credential to exercise an auth code path —
not a real secret. A context-aware reviewer should dismiss this.

Bandit's B101 ("assert detected") also fires here — Phase 9.1 moved
this from an expected "confirm" to an expected "dismiss": an assert in
a pytest test file is the standard, correct way to write a test
assertion, not a risky use of `assert` for a runtime check that would
break under `-O`. This is a genuine false positive in context, not
merely a minor-but-true observation (see _VERDICT_CONTRACT's
confirm-vs-dismiss distinction in nodes.py) — treating it as
must-always-confirm was the original ground truth's own mistake,
found via Phase 9's live dogfood/harness runs, not a prompt problem."""


def test_login_rejects_wrong_password():
    password = "not-a-real-password-testing-only"
    assert authenticate(user="test_user", password=password) is False


def authenticate(user, password):
    raise NotImplementedError
