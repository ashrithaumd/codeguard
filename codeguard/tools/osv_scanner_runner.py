"""OSV-Scanner over npm/yarn/pnpm, Go, Maven/Gradle and NuGet lockfiles
(Apache-2.0, https://github.com/google/osv-scanner).

Pinned at 2.6.0 and installed by hash in its own location (Dockerfile,
/opt/osv-scanner); the runner calls OSV_SCANNER_BIN, falling back to a PATH
lookup outside Docker.

Python is not here. Its check (tools/osv_runner.py) reads the pins a PR adds
to requirements.txt / pyproject.toml and is unchanged; Python's lockfiles
are deliberately never handed to OSV-Scanner (docs/backlog.md).

How it runs:
  * every lockfile is passed explicitly with `-L <kind>:<path>`, so nothing
    else in a repository is ever scanned, and it is written to a numbered
    directory under its own basename, so a repository's path never reaches
    the command line or our filesystem as given;
  * --no-resolve: a pom.xml is read as written, never resolved against the
    Maven repositories it names (a repository picks those);
  * --no-call-analysis=all: nothing is built and no build script runs;
  * a short environment allowlist, so no credential of ours reaches it.

Vulnerability data is live (OSV.dev), like Python's check: a stale database
baked into the image would be wrong the day after it was built. OSV
unreachable (exit 127), the binary missing, a timeout or output we cannot
read is DependencyCheck([], unavailable=True) -- the "Dependency CVE check
unavailable" note, never an empty result that reads as clean.

A PR reports only vulnerabilities that are new at head: one run over the
head and base copies of each changed lockfile, and a head vulnerability is
dropped when the same package in the same lockfile at base already had it
(under any of its aliases). An audit reports everything.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from codeguard.tools.base import resolve_tool_command
from codeguard.tools.metrics import tool_failures_total, tool_run_duration_seconds
from codeguard.tools.models import Finding
from codeguard.tools.osv_runner import TOOL_NAME, DependencyCheck, _severity_from_osv

logger = logging.getLogger(__name__)

EXPECTED_VERSION = "2.6.0"
DEFAULT_TIMEOUT = 120
# A lockfile over this is not scanned and the check says it is incomplete.
MAX_LOCKFILE_BYTES = 20 * 1024 * 1024

# Basename -> OSV-Scanner's own parser name (the same string).
OSV_LOCKFILES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",   # npm, Yarn, pnpm
    "go.mod",                                             # Go (go.sum holds hashes, not versions)
    "pom.xml", "gradle.lockfile", "buildscript-gradle.lockfile",  # Maven, Gradle
    "packages.lock.json",                                 # NuGet
})
# Somebody else's lockfiles, not the repository's own dependencies.
_VENDORED = ("node_modules/", "vendor/", "third_party/")

_ENV_ALLOWLIST = ("PATH", "HOME", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR",
                  "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy")
_NO_PACKAGES = 128  # "No package sources found": nothing to check, not a failure.
_VULNS_FOUND = 1


def is_osv_lockfile(path: str) -> bool:
    path = path.replace("\\", "/")
    if any(path.startswith(d) or f"/{d}" in path for d in _VENDORED):
        return False
    return path.rsplit("/", 1)[-1] in OSV_LOCKFILES


def osv_scanner_command() -> list[str]:
    explicit = os.environ.get("OSV_SCANNER_BIN")
    return [explicit] if explicit else resolve_tool_command("osv-scanner")


def _env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k in _ENV_ALLOWLIST}


def _line_of(content: str, name: str, version: str) -> int:
    """The package's line in its lockfile, best effort: the first line that
    names it, moved to the version line just below when the version is not
    on it (package-lock.json, packages.lock.json, pom.xml). 0 when the
    package cannot be found, as Python's check does."""
    short = name.rsplit(":", 1)[-1].rsplit("/", 1)[-1].lower()
    lines = content.splitlines()
    for i, line in enumerate(lines):
        if name.lower() in line.lower() or short in line.lower():
            for j in range(i, min(i + 10, len(lines))):
                if version in lines[j]:
                    return j + 1
            return i + 1
    return 0


def _version_key(version: str) -> tuple[int, ...]:
    """Numeric parts only ("v1.8.1" -> (1, 8, 1), "2.9.8-rc1" -> (2, 9, 8,
    1)): enough to place a version between two events of one range."""
    key: list[int] = []
    for part in re.split(r"[^0-9]+", version):
        if part:
            key.append(int(part))
    return tuple(key)


def _fixed_for(vuln: dict, name: str, version: str, ecosystem: str) -> str | None:
    """The fix for THIS package at THIS version. A record often lists
    several packages (lodash and lodash-es) and several lines of one
    (minimist 0.x fixed in 0.2.1, 1.x in 1.2.3); the fix named is the one
    closing the range the installed version is in. None when no range
    holds it: no fix named is better than the wrong one."""
    current = _version_key(version)
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != name.lower() or pkg.get("ecosystem", ecosystem) != ecosystem:
            continue
        for rng in affected.get("ranges", []):
            introduced: tuple[int, ...] | None = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = _version_key(event["introduced"])
                elif "fixed" in event and introduced is not None:
                    if introduced <= current < _version_key(event["fixed"]):
                        return event["fixed"]
                    introduced = None
    return None


class _Vuln:
    __slots__ = ("key", "names", "name", "version", "ecosystem", "record")

    def __init__(self, key, names, name, version, ecosystem, record):
        self.key, self.names, self.name, self.version, self.ecosystem, self.record = (
            key, names, name, version, ecosystem, record)


def _vulns(stdout: str, slots: dict[str, tuple[str, str]]) -> list[_Vuln]:
    """One per vulnerability group (OSV-Scanner's own grouping of aliases)
    per package. `slots` maps the path we passed to (side, original path)."""
    out: list[_Vuln] = []
    for result in json.loads(stdout).get("results", []):
        slot = slots.get(result["source"]["path"])
        if slot is None:
            continue
        for pkg in result.get("packages", []):
            info = pkg["package"]
            by_id = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            for group in pkg.get("groups", []):
                ids = group.get("ids") or []
                if not ids:
                    continue
                record = by_id.get(ids[0], {"id": ids[0]})
                names = frozenset(ids) | frozenset(group.get("aliases") or [])
                out.append(_Vuln((slot, info.get("ecosystem", ""), info["name"]), names,
                                 info["name"], info.get("version", ""), info.get("ecosystem", ""), record))
    return out


def _finding(path: str, content: str, v: _Vuln) -> Finding:
    vuln_id = v.record.get("id", "unknown")
    summary = v.record.get("summary") or (v.record.get("details") or "")[:200]
    message = f"{v.name}@{v.version} has a known vulnerability ({vuln_id}): {summary}"
    fixed = _fixed_for(v.record, v.name, v.version, v.ecosystem)
    if fixed:
        message += f" Fixed in {fixed}."
    line = _line_of(content, v.name, v.version)
    return Finding.create(file=path, start_line=line, end_line=line, severity=_severity_from_osv(v.record),
                          source_tool=TOOL_NAME, rule_id=vuln_id, message=message)


def _run(sides: dict[str, dict[str, str]], timeout: int) -> list[_Vuln] | None:
    """One OSV-Scanner run over every (side, path) -> content. None when the
    check did not happen."""
    tmp_dir = tempfile.mkdtemp(prefix="codeguard-osv-scanner-")
    start = time.perf_counter()
    slots: dict[str, tuple[str, str]] = {}
    cmd = osv_scanner_command() + ["scan", "source", "--format", "json", "--no-resolve",
                                   "--no-call-analysis=all", "--verbosity", "error"]
    try:
        n = 0
        for side, files in sides.items():
            for path, content in files.items():
                dest = Path(tmp_dir) / side / str(n) / path.replace("\\", "/").rsplit("/", 1)[-1]
                n += 1
                dest.parent.mkdir(parents=True)
                dest.write_text(content, encoding="utf-8")
                slots[str(dest)] = (side, path)
                cmd += ["-L", f"{dest.name}:{dest}"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=_env())
        if proc.returncode == _NO_PACKAGES:
            return []
        if proc.returncode not in (0, _VULNS_FOUND):
            raise RuntimeError(f"exit {proc.returncode}: {(proc.stderr or '').strip()[-500:]}")
        return _vulns(proc.stdout, slots)
    except Exception as exc:
        tool_failures_total.labels(tool="osv-scanner").inc()
        logger.warning("osv-scanner did not run on %d lockfile(s): %r -- dependency check unavailable", len(slots), exc)
        return None
    finally:
        tool_run_duration_seconds.labels(tool="osv-scanner").observe(time.perf_counter() - start)
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _too_large(files: dict[str, str]) -> bool:
    return any(len(c.encode("utf-8")) > MAX_LOCKFILE_BYTES for c in files.values())


def scan_lockfiles(files: dict[str, str], timeout: int = DEFAULT_TIMEOUT) -> DependencyCheck:
    """An audit: every vulnerability in every lockfile."""
    if not files:
        return DependencyCheck([])
    if _too_large(files):
        return DependencyCheck([], unavailable=True)
    vulns = _run({"head": files}, timeout)
    if vulns is None:
        return DependencyCheck([], unavailable=True)
    return DependencyCheck([_finding(v.key[0][1], files[v.key[0][1]], v) for v in vulns])


def scan_pr_lockfiles(
    head: dict[str, str], base: dict[str, str], base_paths: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> DependencyCheck:
    """A PR: vulnerabilities in the head copy of each changed lockfile that
    its base copy did not already have. `base` is keyed by base path;
    `base_paths` maps a renamed lockfile's head path to it (default: the
    same path). A lockfile with no base copy is new, so all of it is."""
    if not head:
        return DependencyCheck([])
    if _too_large(head) or _too_large(base):
        return DependencyCheck([], unavailable=True)
    vulns = _run({"head": head, "base": base}, timeout)
    if vulns is None:
        return DependencyCheck([], unavailable=True)
    base_paths = base_paths or {}
    known: dict[tuple, set[str]] = {}
    for v in vulns:
        (side, path), eco, name = v.key
        if side == "base":
            known.setdefault((path, eco, name), set()).update(v.names)
    findings = []
    for v in vulns:
        (side, path), eco, name = v.key
        if side != "head":
            continue
        if v.names & known.get((base_paths.get(path, path), eco, name), set()):
            continue
        findings.append(_finding(path, head[path], v))
    return DependencyCheck(findings)


def combine(python: DependencyCheck, lockfiles: DependencyCheck) -> DependencyCheck:
    """Python's findings first, exactly as they were; either check not
    happening is the note."""
    return DependencyCheck(list(python.findings) + list(lockfiles.findings),
                           python.unavailable or lockfiles.unavailable)
