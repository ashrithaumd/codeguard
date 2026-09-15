"""A genuine shell injection — user_filename flows straight into a
shell=True subprocess call. Bandit's B602/B605 should fire, and
review_security should confirm it: an attacker who controls
user_filename controls the shell command."""

import subprocess


def list_matching_files(user_filename):
    subprocess.run(f"ls -la {user_filename}", shell=True)
