"""Uses the value directly and handles None itself: unaffected."""

from config.settings import get_setting


def label():
    value = get_setting("region")
    return value.upper() if value else "unknown"
