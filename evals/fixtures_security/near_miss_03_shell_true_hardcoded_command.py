"""Bandit's B602/B605 flags any shell=True subprocess call regardless of
whether the command string is attacker-influenced. Here the entire
command is a fixed, hardcoded literal with no variable interpolation —
there's no attacker-controlled input reaching the shell. A context-
aware reviewer should dismiss this (though switching off shell=True
entirely would still be better practice in general)."""

import subprocess


def restart_local_cache_service():
    subprocess.run("systemctl restart local-cache.service", shell=True)
