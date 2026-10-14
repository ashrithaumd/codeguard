"""zizmor over GitHub Actions workflows (MIT, https://github.com/zizmorcore/zizmor).

Pinned at 1.30.1 and installed by hash in its own environment
(Dockerfile, /opt/zizmor); the runner calls ZIZMOR_BIN, falling back to a
PATH lookup outside Docker. Always offline (--offline and ZIZMOR_OFFLINE),
never handed a GitHub token, never reading a repository's own zizmor
config: the rules that run are the ones pinned here.

Only workflow files (languages.language_of == "GitHub Actions") are handed
over. A malformed workflow is skipped by zizmor itself with a warning and
the rest are still audited. --no-exit-codes: like every runner here, the
exit code is never a gate (tools/base.py); unparseable output is "did not
run".
"""

from __future__ import annotations

import json
import os

import yaml

from codeguard.severity import Severity
from codeguard.tools.base import resolve_original_path, resolve_tool_command, run_tool_on_pr
from codeguard.tools.models import Finding

TOOL_NAME = "zizmor"
EXPECTED_VERSION = "1.30.1"
DEFAULT_TIMEOUT = 60

_SEVERITY = {"High": Severity.HIGH, "Medium": Severity.MEDIUM, "Low": Severity.LOW}
_CONFIDENCE = {"High": 1.0, "Medium": 0.6, "Low": 0.3}
_TOKEN_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "ZIZMOR_GITHUB_TOKEN")


def zizmor_command() -> list[str]:
    explicit = os.environ.get("ZIZMOR_BIN")
    return [explicit] if explicit else resolve_tool_command(TOOL_NAME)


def zizmor_env() -> dict[str, str]:
    """Ours, minus any GitHub token (an online audit would use one), plus
    zizmor's own offline switch in case a flag is ever dropped."""
    env = {k: v for k, v in os.environ.items() if k not in _TOKEN_VARS}
    env["ZIZMOR_OFFLINE"] = "true"
    return env


def _build_cmd(tmp_dir: str) -> list[str]:
    return zizmor_command() + [
        "--offline", "--no-config", "--no-progress", "--no-exit-codes",
        "--format", "json", "--min-severity", "low", tmp_dir,
    ]


def _primary(locations: list[dict]) -> dict | None:
    for loc in locations:
        if loc.get("symbolic", {}).get("kind") == "Primary":
            return loc
    return locations[0] if locations else None


def _parse(stdout: str, tmp_dir: str) -> list[Finding]:
    findings: list[Finding] = []
    for result in json.loads(stdout):
        severity = _SEVERITY.get(result["determinations"]["severity"])
        if result.get("ignored") or severity is None:
            continue
        loc = _primary(result.get("locations", []))
        if loc is None:
            continue
        path = loc["symbolic"]["key"]["Local"]["verbatim_path"]
        start = loc["concrete"]["location"]["start_point"]["row"] + 1
        end = loc["concrete"]["location"]["end_point"]["row"] + 1
        annotation = loc["symbolic"].get("annotation", "")
        message = result["desc"] + (f": {annotation}" if annotation else "")
        findings.append(Finding.create(
            file=resolve_original_path(tmp_dir, path), start_line=start, end_line=max(start, end),
            severity=severity, source_tool=TOOL_NAME, rule_id=result["ident"], message=message,
            confidence=_CONFIDENCE.get(result["determinations"].get("confidence"), 1.0),
        ))
    return findings


INVALID_YAML = "not scanned (invalid YAML)"


def _workflows(files: dict[str, str]) -> dict[str, str]:
    from codeguard.languages import language_of

    return {p: c for p, c in files.items() if language_of(p) == "GitHub Actions"}


def _parses(content: str) -> bool:
    try:
        yaml.safe_load(content)
    except yaml.YAMLError:
        return False
    return True


def invalid_workflows(files: dict[str, str]) -> list[tuple[str, str]]:
    """[(path, reason)] for each workflow that is not valid YAML. zizmor
    skips such a file with a warning that does not name it, so it is found
    here first and listed with the files not reviewed (GitHub will not run
    it either)."""
    return [(p, INVALID_YAML) for p, c in sorted(_workflows(files).items()) if not _parses(c)]


def run_zizmor(files: dict[str, str], timeout: int = DEFAULT_TIMEOUT) -> list[Finding]:
    in_scope = {p: c for p, c in _workflows(files).items() if _parses(c)}
    if not in_scope:
        return []
    return run_tool_on_pr(TOOL_NAME, _build_cmd, _parse, in_scope, timeout, env=zizmor_env())
