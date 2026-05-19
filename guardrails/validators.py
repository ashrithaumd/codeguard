import re
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_CODE_LENGTH = 10000
MIN_CODE_LENGTH = 10

PROMPT_INJECTION_PATTERNS = [
    r"ignore previous instructions",
    r"ignore all instructions",
    r"disregard your instructions",
    r"you are now",
    r"act as",
    r"pretend you are",
    r"forget your previous",
    r"new instructions",
    r"system prompt",
    r"jailbreak",
]

PII_PATTERNS = {
    "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "phone": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
}

CODE_INDICATORS = [
    "def ", "function ", "class ", "import ",
    "var ", "let ", "const ", "public ",
    "private ", "return ", "if ", "for ",
    "while ", "print(", "console.log",
    "//", "/*", "#", "->", "=>", "{", "}"
]


def validate_input(code: str) -> tuple[bool, str]:
    """
    Main input validation function.
    Runs all checks on submitted code.

    Returns:
        Tuple of (is_valid, error_message)
        is_valid = True means code passed all checks
        is_valid = False means code failed a check
    """
    logger.info("[Guardrails] Running input validation...")

    is_valid, message = check_empty(code)
    if not is_valid:
        return False, message

    is_valid, message = check_length(code)
    if not is_valid:
        return False, message

    is_valid, message = check_is_code(code)
    if not is_valid:
        return False, message

    is_valid, message = check_prompt_injection(code)
    if not is_valid:
        return False, message

    logger.info("[Guardrails] Input validation passed.")
    return True, "Validation passed."


def check_empty(code: str) -> tuple[bool, str]:
    """Check if the input is empty."""
    if not code or not code.strip():
        logger.warning("[Guardrails] Empty input detected.")
        return False, "Please submit some code to review."
    return True, ""


def check_length(code: str) -> tuple[bool, str]:
    """Check if the code is within acceptable length limits."""
    if len(code) < MIN_CODE_LENGTH:
        logger.warning("[Guardrails] Input too short.")
        return False, "Code is too short to review. Please submit at least 10 characters."

    if len(code) > MAX_CODE_LENGTH:
        logger.warning(f"[Guardrails] Input too large: {len(code)} characters.")
        return False, f"Code exceeds maximum length of {MAX_CODE_LENGTH} characters. Please submit a smaller file."

    return True, ""


def check_is_code(code: str) -> tuple[bool, str]:
    """Check if the input looks like actual code."""
    code_lower = code.lower()
    matches = sum(1 for indicator in CODE_INDICATORS if indicator.lower() in code_lower)

    if matches < 2:
        logger.warning("[Guardrails] Input does not appear to be code.")
        return False, "Input does not appear to be code. Please submit a valid code snippet."

    return True, ""


def check_prompt_injection(code: str) -> tuple[bool, str]:
    """Check for prompt injection attempts."""
    code_lower = code.lower()

    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, code_lower):
            logger.warning(f"[Guardrails] Prompt injection attempt detected: {pattern}")
            return False, "Invalid input detected. Please submit valid code only."

    return True, ""


def check_pii(code: str) -> dict:
    """
    Scan code for personally identifiable information.
    Returns a dict of PII types found.
    Does NOT block the review - just warns the user.
    """
    pii_found = {}

    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, code)
        if matches:
            pii_found[pii_type] = len(matches)
            logger.warning(f"[Guardrails] PII detected: {pii_type} ({len(matches)} instances)")

    return pii_found


def validate_output(report: str) -> tuple[bool, str]:
    """
    Validate the final report output.
    Ensures the report is properly formed before showing to user.
    """
    if not report or not report.strip():
        return False, "Report generation failed. Please try again."

    if len(report) < 50:
        return False, "Report is incomplete. Please try again."

    return True, report