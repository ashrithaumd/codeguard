"""A genuine weak-hash misuse — MD5 used to hash a password for storage.
Bandit's B324 should fire, and review_security should confirm it:
MD5 is not appropriate for password storage, no mitigating context."""

import hashlib


def hash_password_for_storage(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
