"""Dependency-vulnerability lookup via OSV.dev — deterministic,
no LLM, no API key needed (OSV's query API is public and free). This
runner has a fundamentally different shape than Bandit/Semgrep/Ruff:
those scan a file's CONTENT; this one needs to know what CHANGED in a
diff, since only a newly-added or newly-bumped exact pin is worth
querying — an unchanged, already-reviewed dependency shouldn't
resurface the same finding on every subsequent PR that happens to touch
the same file. That's why it doesn't live in tools/run_all.py's RUNNERS
tuple: those all take `files` alone; this one needs `patches` too.

Never blocks a review over OSV being unreachable — same "never crash
the review" discipline as every other tool runner (see tools/base.py's
own docstring): a network failure here just means zero dependency
findings for this PR, not a failed job.
"""

from __future__ import annotations

import logging
import re

import requests

from codeguard.diff.filters import DEPENDENCY_MANIFEST_FILENAMES
from codeguard.severity import Severity
from codeguard.tools.models import Finding

logger = logging.getLogger(__name__)

TOOL_NAME = "osv"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
DEFAULT_TIMEOUT = 15

# requirements.txt: "name==1.2.3", optionally with extras ("name[extra]==1.2.3")
# or a trailing environment marker (";...") — both ignored for lookup
# purposes; the bare name+version pin is all OSV's query needs.
_REQUIREMENTS_PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*?)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.\-+]+)\s*(?:;.*)?$"
)
# pyproject.toml: a quoted PEP-508-ish dependency string inside an array,
# e.g. `"pyyaml==5.3"`. Only the exact-pin ("==") form is queryable
# against one specific version — a range (">=2.19.0,<3") has no single
# version to look up; widening that to "could resolve to a vulnerable
# version" would need a real dependency resolver, not a regex over a
# diff, so ranges are deliberately skipped rather than guessed at.
_PYPROJECT_PIN_RE = re.compile(
    r'"([A-Za-z0-9][A-Za-z0-9._-]*?)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.\-+]+)"'
)


def _iter_added_pins(filename: str, patch: str):
    """Yields (name, version) for every exact-version pin on an ADDED
    line of this file's own patch — never a removed or unchanged line.
    """
    pattern = _REQUIREMENTS_PIN_RE if filename == "requirements.txt" else _PYPROJECT_PIN_RE
    for line in patch.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        match = pattern.search(line[1:])
        if match:
            yield match.group(1).lower(), match.group(2)


def _find_pin_line(content: str, name: str, version: str) -> int:
    """Best-effort line lookup in the file's own new content — a plain
    substring match, not a re-parse of the dependency syntax, since by
    this point we already know the pin exists (we found it in the
    patch); this just needs the line number for the Finding.
    """
    for i, line in enumerate(content.splitlines(), start=1):
        if name in line.lower() and version in line:
            return i
    return 0


def _severity_from_osv(vuln: dict) -> Severity:
    """OSV doesn't normalize severity the consistent way Bandit/Semgrep
    do — some records carry a database_specific severity string (GHSA
    style: LOW/MODERATE/HIGH/CRITICAL), some carry a bare CVSS numeric
    score, some carry a full CVSS vector string, many carry nothing at
    all. Absent something confidently parseable, default to MEDIUM
    rather than guess HIGH: a known CVE is always worth a human's
    attention, but "OSV has a record for this exact version" alone
    isn't the same confidence as a scanner that inspected this specific
    code's own usage of it.
    """
    db_severity = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    mapped = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM, "LOW": Severity.LOW}
    if db_severity in mapped:
        return mapped[db_severity]

    for entry in vuln.get("severity", []):
        score = str(entry.get("score", ""))
        try:
            numeric = float(score)
        except ValueError:
            continue  # a full CVSS vector string, not a bare number — skip rather than hand-parse it
        if numeric >= 9.0:
            return Severity.CRITICAL
        if numeric >= 7.0:
            return Severity.HIGH
        if numeric >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    return Severity.MEDIUM


def _fixed_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _finding_for_vuln(path: str, line: int, name: str, version: str, vuln: dict) -> Finding:
    vuln_id = vuln.get("id", "unknown")
    summary = vuln.get("summary") or (vuln.get("details") or "")[:200]
    message = f"{name}=={version} has a known vulnerability ({vuln_id}): {summary}"
    fixed = _fixed_version(vuln)
    if fixed:
        message += f" Fixed in {fixed}."
    return Finding.create(
        file=path, start_line=line, end_line=line, severity=_severity_from_osv(vuln),
        source_tool=TOOL_NAME, rule_id=vuln_id, message=message,
    )


def _fetch_vuln_detail(vuln_id: str, timeout: int) -> dict | None:
    try:
        resp = requests.get(OSV_VULN_URL.format(id=vuln_id), timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException:
        logger.warning("failed to fetch OSV vuln detail for %s, using bare id only", vuln_id, exc_info=True)
        return None


def check_dependency_updates(
    files: dict[str, str], patches: dict[str, str], timeout: int = DEFAULT_TIMEOUT,
) -> list[Finding]:
    """One batched OSV query for every newly-added/bumped exact pin
    across every touched requirements.txt/pyproject.toml in this PR —
    never one request per package, which wouldn't scale past a handful
    of dependency bumps in one PR. A per-vuln follow-up call fetches
    full detail (summary/severity/fixed-version) for whatever the batch
    query actually flagged, since OSV's batch endpoint itself returns
    only bare vuln IDs.
    """
    pins: list[tuple[str, str, str]] = []  # (path, name, version)
    for path, patch in patches.items():
        filename = path.rsplit("/", 1)[-1]
        if filename not in DEPENDENCY_MANIFEST_FILENAMES:
            continue
        for name, version in _iter_added_pins(filename, patch):
            pins.append((path, name, version))

    if not pins:
        return []

    queries = [{"package": {"name": name, "ecosystem": "PyPI"}, "version": version} for _, name, version in pins]
    try:
        resp = requests.post(OSV_BATCH_URL, json={"queries": queries}, timeout=timeout)
        resp.raise_for_status()
        results = resp.json().get("results", [])
    except requests.RequestException:
        logger.warning("OSV batch query failed, skipping dependency check for this PR", exc_info=True)
        return []

    if len(results) != len(pins):
        # Found via CodeGuard's own review of one of its own PRs: OSV's
        # batch endpoint is documented as one result per query, same order,
        # but nothing here enforces that contract — a short or
        # mismatched response would otherwise misalign every pin after
        # the gap if paired up positionally with a bare zip(). Indexing
        # into `results` defensively below (never zip()) means a
        # length mismatch can only ever mean "treat the unmatched
        # pin(s) as no result," never a silent misattribution.
        logger.warning(
            "OSV batch response had %d result(s) for %d quer(ies); some pins will be treated as unchecked",
            len(results), len(pins),
        )

    findings: list[Finding] = []
    for i, (path, name, version) in enumerate(pins):
        result = results[i] if i < len(results) else None
        vuln_ids = [v["id"] for v in (result or {}).get("vulns", [])]
        if not vuln_ids:
            continue
        line = _find_pin_line(files.get(path, ""), name, version)
        for vuln_id in vuln_ids:
            vuln = _fetch_vuln_detail(vuln_id, timeout) or {"id": vuln_id}
            findings.append(_finding_for_vuln(path, line, name, version, vuln))
    return findings
