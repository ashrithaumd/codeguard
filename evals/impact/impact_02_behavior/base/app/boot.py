"""Startup: relies on KeyError to fall back to a default region."""

from config.settings import get_setting


def region():
    try:
        return get_setting("region_override")
    except KeyError:
        return get_setting("region")
