"""Both dimensions at once: single-letter names AND a real untested
edge-case branch (empty list) with no accompanying test evident
anywhere in view."""


def a(l):
    if len(l) == 0:
        return None
    s = 0
    for x in l:
        s = s + x
    return s / len(l)
