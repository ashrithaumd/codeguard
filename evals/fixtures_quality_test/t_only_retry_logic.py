"""Test-coverage issue only: well-named retry-with-backoff logic with
real branching (success, retryable failure, exhausted retries) and no
test evident anywhere in view — nothing here is a naming, complexity,
or duplication problem."""

import time


def fetch_with_retries(fetch_fn, max_attempts=3):
    for attempt in range(max_attempts):
        try:
            return fetch_fn()
        except ConnectionError:
            if attempt == max_attempts - 1:
                raise
            time.sleep(2 ** attempt)
