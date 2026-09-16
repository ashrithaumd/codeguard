"""Near-miss for the Quality agent — added in Phase 9.1 after dogfooding
CodeGuard's own repo produced a confidently-wrong finding on the real
version of this code (codeguard/pipeline/llm_call.py:181, see
evals/RESULTS.md's "honestly wrong finding" section): the agent claimed
`getattr(obj, "field", 0) or 0` is redundant because "the default
already handles the missing attribute case." That's true but incomplete
— `or 0` also covers the attribute being PRESENT but explicitly `None`,
which `getattr`'s own default does not catch. Applying the agent's own
suggested fix (removing `or 0`) would reintroduce a real bug for any
SDK response where the field is populated as None rather than omitted.

expect_quality_flag: false — a well-reasoned reviewer should recognize
the `or 0` is doing real work here, not flag it as redundant.
"""


def extract_cache_tokens(usage) -> int:
    # usage.cache_read_tokens can be either ABSENT (older SDK versions,
    # getattr's default of 0 covers this) or PRESENT but explicitly
    # None (newer versions populate every field, using None for "not
    # applicable") — `or 0` is required to normalize both cases to 0.
    return getattr(usage, "cache_read_tokens", 0) or 0
