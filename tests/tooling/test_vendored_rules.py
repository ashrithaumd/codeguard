"""Vendored third-party Semgrep rules: pinned, verified, licensed.

GitLab sast-rules v2.10.1 (MIT, (c) GitLab Inc.), whose Go rules derive
from gosec (Apache-2.0). Only rule YAML is vendored: the archive's Java/C#
test samples carry LGPL-3.0 headers (find-sec-bugs, security-code-scan) and
are not ours to ship. Every file is listed in MANIFEST.sha256 and must match
it, so a rule cannot change without the manifest -- and the review -- changing
too. Not loaded by the Python scan path (tests/tools/test_semgrep_pinned_offline.py).

NOT the Semgrep Registry (its license forbids distribution and service use)
and NOT opengrep-rules (Commons Clause).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

VENDOR = Path(__file__).resolve().parents[2] / "rules_vendor" / "gitlab-sast-rules"
META = {"LICENSE", "NOTICE", "MANIFEST.sha256", "README.md"}
LANGUAGES = {"javascript", "go", "java", "csharp"}
ALLOWED_HEADERS = {"# License: MIT (c) GitLab Inc.", "# License: Apache 2.0 (c) gosec"}


def _rule_files():
    return sorted(p for p in VENDOR.rglob("*") if p.is_file() and p.name not in META)


def _manifest():
    out = {}
    for line in (VENDOR / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            digest, path = line.split(None, 1)
            out[path.strip()] = digest
    return out


def test_license_notice_and_manifest_are_present():
    for name in ("LICENSE", "NOTICE", "MANIFEST.sha256"):
        assert (VENDOR / name).is_file(), name
    notice = (VENDOR / "NOTICE").read_text(encoding="utf-8")
    for must in ("v2.10.1", "627a73135374fdb9122eb3dcca268ea0fbb11d889d1126c6c52fd28b9df2236b",
                 "MIT", "gosec", "Apache"):
        assert must in notice, must


def test_only_rule_yaml_for_the_four_planned_languages_is_vendored():
    files = _rule_files()
    assert files, "nothing vendored"
    assert {p.suffix for p in files} == {".yml"}
    assert {p.relative_to(VENDOR).parts[0] for p in files} == LANGUAGES


def test_every_file_matches_the_manifest_and_nothing_is_unlisted():
    manifest = _manifest()
    on_disk = {p.relative_to(VENDOR).as_posix(): p for p in _rule_files()}
    assert set(manifest) == set(on_disk)
    for rel, path in on_disk.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest[rel], rel


def _normalized(header: str) -> str:
    """One upstream file reads "# License: License: MIT (c) GitLab Inc." --
    a typo in GitLab's header, kept verbatim in the vendored copy."""
    while header.startswith("# License: License:"):
        header = "# License:" + header[len("# License: License:"):]
    return header


def test_every_rule_carries_a_permissive_license_header():
    for path in _rule_files():
        headers = {_normalized(line.strip()) for line in path.read_text(encoding="utf-8").splitlines()
                   if line.strip().lower().startswith("# license:")}
        assert headers and headers <= ALLOWED_HEADERS, (path.name, headers)


def test_every_file_is_a_semgrep_ruleset():
    for path in _rule_files():
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(doc, dict) and isinstance(doc.get("rules"), list) and doc["rules"], path.name
