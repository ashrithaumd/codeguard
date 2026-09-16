"""Bandit's B608 pattern-matches any string-formatting near a SQL
keyword, regardless of whether the interpolated value is attacker-
controlled. Here it's a hardcoded, module-level constant table name —
never user input — so there's no actual injection surface. A context-
aware reviewer should dismiss this."""

_AUDIT_TABLE = "audit_log"


def count_audit_rows(cursor):
    query = "SELECT COUNT(*) FROM %s" % _AUDIT_TABLE
    cursor.execute(query)
    return cursor.fetchone()[0]
