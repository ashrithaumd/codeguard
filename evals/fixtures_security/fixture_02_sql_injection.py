"""A genuine SQL injection — the WHERE clause is built by string-
formatting a caller-supplied value directly into the query text.
Bandit's B608 should fire, and review_security should confirm it."""


def find_user_by_name(cursor, name):
    query = "SELECT * FROM users WHERE name = '%s'" % name
    cursor.execute(query)
    return cursor.fetchone()
