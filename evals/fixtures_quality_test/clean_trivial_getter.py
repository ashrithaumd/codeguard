"""Clean fixture: well-named, trivial pass-through property — nothing
for either agent to flag."""


class UserProfile:
    def __init__(self, display_name):
        self._display_name = display_name

    @property
    def display_name(self):
        return self._display_name
