"""The version of the structured audit report (audits.report_json).

Its own module so the api can read it without importing codeguard.cli,
which pulls in tiktoken and the scanner runners. cli.build_report_data
writes this version; the audit page renders only a version it knows and
shows the raw markdown for anything else.

Bump it when a field the page reads changes meaning or goes away. Adding
a field the page can ignore is not a bump.
"""

REPORT_DATA_VERSION = 1

# What every surface says when verdict calls failed and the scanner's raw
# findings are shown instead (Finding.unreviewed): the audit report and
# page, the review detail page and the PR summary. One string, so the
# wording cannot drift between them.
UNREVIEWED_NOTICE_TEXT = "AI review unavailable for {n} finding(s); shown unreviewed."
