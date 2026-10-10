"""Every scanner on the generic path, in one call, for the audit and the PR
path alike: the second Semgrep pass (vendored GitLab rules and our own
rules_lang/, JS/TS, Go, Java, C# and Dockerfiles) and zizmor (GitHub
Actions). Each runner keeps only the files in its own languages."""

from __future__ import annotations

from codeguard.tools.models import Finding
from codeguard.tools.semgrep_runner import run_vendor_rules
from codeguard.tools.zizmor_runner import run_zizmor


def run_generic_scanners(files: dict[str, str]) -> list[Finding]:
    return run_vendor_rules(files) + run_zizmor(files)
