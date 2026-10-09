"""Settings lookup."""

_VALUES = {"region": "us-east-1"}


def get_setting(name):
    """The value for `name`. Raises KeyError when it is not set."""
    return _VALUES[name]
