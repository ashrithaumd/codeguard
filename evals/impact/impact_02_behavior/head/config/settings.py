"""Settings lookup."""

_VALUES = {"region": "us-east-1"}


def get_setting(name):
    """The value for `name`, or None when it is not set."""
    return _VALUES.get(name)
