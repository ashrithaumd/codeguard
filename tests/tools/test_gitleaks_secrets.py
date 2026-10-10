"""Secrets in every non-Python file type (tools/gitleaks_runner.py).

THE VALUE NEVER LEAVES MEMORY. Gitleaks runs with --redact, so its own
report never contains a secret. The runner finds the value in the content
it already holds (aligning Gitleaks' redacted Match against the line),
classifies its SHAPE, optionally computes a KEYED id, and drops it. What is
kept: rule, file, line, the shape hint (length, prefix style, kind), and
the id. Nothing about a secret is sent to a model: the shape classifier
alone decides (placeholder-like -> not reported; anything else -> a HIGH
finding).

Every key below is generated at test time from a seeded generator: realistic
shapes, never real, never committed.
"""

from __future__ import annotations

import json
import logging
import random
import string

import pytest

from codeguard.config import RepoConfig
from codeguard.tools.gitleaks_runner import SecretScan, extract_value, scan_secrets, sparse_from_patch

ALNUM = string.ascii_letters + string.digits


def _key(seed: int, prefix: str = "ghp_", n: int = 36) -> str:
    rng = random.Random(seed)
    return prefix + "".join(rng.choice(ALNUM) for _ in range(n))


def _everything_stored(scan: SecretScan) -> str:
    """Every byte the scan result could carry anywhere: findings (all text
    fields), their JSON, the counts."""
    parts = [repr(scan)]
    for f in scan.findings:
        parts += [f.message, f.title, f.what, f.why, f.fix, f.fingerprint, json.dumps(f.model_dump(), default=str)]
    return "\n".join(parts)


# --------------------------------------------------------------------------
# Locating the value without Gitleaks reporting it
# --------------------------------------------------------------------------

def test_extract_value_when_the_match_is_the_secret():
    line = '  github_token: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"'
    assert extract_value(line, match="REDACTED", start_col=18, end_col=57) == "ghp_abcdefghijklmnopqrstuvwxyz0123456789"


def test_extract_value_when_the_match_carries_its_context():
    line = 'service: {api_key: "Zx81Kq0pLmN3vB7tR2yW9eU4iO6aS5dF"}'
    assert extract_value(line, match='api_key: "REDACTED"', start_col=12, end_col=52) == "Zx81Kq0pLmN3vB7tR2yW9eU4iO6aS5dF"


def test_extract_value_refuses_what_it_cannot_align():
    assert extract_value("nothing here", match='key="REDACTED"', start_col=1, end_col=5) is None


# --------------------------------------------------------------------------
# The canary: a real-looking key must never appear in anything we keep
# --------------------------------------------------------------------------

def test_a_secret_is_found_and_its_value_is_nowhere_in_the_result(caplog):
    key = _key(1)
    content = f"app:\n  name: demo\n  github_token: \"{key}\"\n"
    with caplog.at_level(logging.DEBUG):
        scan = scan_secrets({"config/app.yml": content}, RepoConfig())

    [f] = scan.findings
    assert (f.file, f.start_line, f.source_tool, f.rule_id) == ("config/app.yml", 3, "gitleaks", "gitleaks.github-pat")
    assert f.severity.name == "HIGH"
    assert "40-char github-style token, high-entropy" in f.message
    assert key not in _everything_stored(scan)
    assert key not in caplog.text
    assert key[4:20] not in _everything_stored(scan)  # not even a fragment


def test_a_realistic_key_beside_a_this_is_fake_comment_is_still_confirmed():
    """The adversarial case: whoever wrote the key wrote the comment too."""
    key = _key(2)
    content = f"# this is a fake key for the docs, do not worry\nGITHUB_TOKEN={key}\n"
    scan = scan_secrets({".env.example": content}, RepoConfig())
    assert [f.start_line for f in scan.findings] == [2]


def test_a_placeholder_shaped_value_is_not_reported_only_counted():
    """Token-shaped, so Gitleaks reports it, but carrying a marker word, so
    the shape is placeholder-like. (Gitleaks drops most placeholders itself,
    by entropy; these are the ones that reach the classifier.)"""
    rest = _key(10, prefix="", n=29)
    content = f'a: "ghp_example{rest}"\nb: "ghp_PLACEHOLDER{rest[:25]}"\nGITHUB_TOKEN=ghp_dummy{rest}xx\n'
    scan = scan_secrets({"config.yml": content}, RepoConfig())
    assert scan.findings == []
    assert scan.placeholders == 3


# --------------------------------------------------------------------------
# Scope: Python untouched; ignore rules; PR = added lines only
# --------------------------------------------------------------------------

def test_python_files_are_never_scanned_here():
    key = _key(3)
    scan = scan_secrets({"settings.py": f'TOKEN = "{key}"\n', "app.yml": "a: 1\n"}, RepoConfig())
    assert scan.findings == [] and scan.placeholders == 0


def test_ignored_vendored_and_lockfiles_are_left_out():
    key = _key(4)
    files = {"skip/conf.yml": f"t: {key}\n", "node_modules/x/conf.yml": f"t: {key}\n",
             "vendor/conf.yml": f"t: {key}\n", "package-lock.json": f'{{"t": "{key}"}}\n',
             "docs/setup.md": f"Use GITHUB_TOKEN={key}\n"}
    scan = scan_secrets(files, RepoConfig(ignored_paths=["skip/*"]))
    assert [f.file for f in scan.findings] == ["docs/setup.md"]  # docs ARE scanned: keys get pasted into READMEs


def test_a_sparse_pr_file_keeps_added_lines_at_their_head_line_numbers():
    patch = "@@ -1,3 +1,4 @@\n a: 1\n-b: 2\n+b: 3\n+token: x\n c: 4\n"
    assert sparse_from_patch(patch) == "\nb: 3\ntoken: x\n"


def test_in_a_pr_only_a_newly_added_secret_is_reported_at_its_line():
    old_key, new_key = _key(5), _key(6)
    patch = (f"@@ -1,3 +1,4 @@\n old_token: {old_key}\n-b: 2\n+b: 3\n+new_token: {new_key}\n c: 4\n")
    scan = scan_secrets({"conf.yml": sparse_from_patch(patch)}, RepoConfig())
    assert [(f.file, f.start_line) for f in scan.findings] == [("conf.yml", 3)]


# --------------------------------------------------------------------------
# The keyed id
# --------------------------------------------------------------------------

def test_the_same_secret_has_the_same_keyed_id_and_it_is_not_a_plain_hash(monkeypatch):
    import hashlib

    from codeguard.tools import gitleaks_runner
    monkeypatch.setattr(gitleaks_runner, "_id_key", lambda: b"test-key")
    key = _key(7)
    scan = scan_secrets({"a.yml": f"t: {key}\n", "b.env": f"T={key}\n"}, RepoConfig())
    ids = {f.message.split("secret id ")[1].rstrip(").") for f in scan.findings}
    assert len(scan.findings) == 2 and len(ids) == 1
    [secret_id] = ids
    assert secret_id not in hashlib.sha256(key.encode()).hexdigest()


def test_no_key_configured_means_no_id_at_all(monkeypatch):
    from codeguard.tools import gitleaks_runner
    monkeypatch.setattr(gitleaks_runner, "_id_key", lambda: None)
    scan = scan_secrets({"a.yml": f"t: {_key(8)}\n"}, RepoConfig())
    assert scan.findings and "secret id" not in scan.findings[0].message


@pytest.mark.parametrize("bad", ["", None])
def test_nothing_to_scan(bad):
    assert scan_secrets({} if bad is None else {"a.yml": bad}, RepoConfig()).findings == []


def test_settings_that_cannot_load_mean_no_id_never_a_failed_scan(monkeypatch):
    """Found by the smoke test: get_settings() raises when ANTHROPIC_API_KEY
    is unset, and the scan crashed over its optional id."""
    from codeguard.tools import gitleaks_runner

    def broken():
        raise ValueError("anthropic_api_key: Field required")
    monkeypatch.setattr(gitleaks_runner, "get_settings", broken)
    scan = scan_secrets({"a.yml": f"t: {_key(11)}\n"}, RepoConfig())
    assert len(scan.findings) == 1 and "secret id" not in scan.findings[0].message
