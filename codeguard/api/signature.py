import hashlib
import hmac


def is_valid_signature(secret: str, raw_body: bytes, header_value: str | None) -> bool:
    """Verify a GitHub webhook's HMAC-SHA256 signature.

    Verification must run against the raw request body bytes exactly as
    received — never a re-serialized/parsed version — since any byte
    difference (key order, whitespace, escaping) produces an unrelated
    digest. Comparison uses hmac.compare_digest rather than `==` to avoid
    a timing side-channel: `==` short-circuits on the first mismatched
    byte, so its running time leaks how many leading bytes matched;
    compare_digest is constant-time regardless of where a mismatch is.

    Fails closed: a missing or malformed header is treated identically
    to a wrong signature — reject, never raise.
    """
    if not header_value or not header_value.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header_value)
