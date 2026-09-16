"""Regression coverage for codeguard.github.auth._load_private_key —
the env-var-vs-file precedence Phase 10's Azure deployment needs
(Container Apps secrets are env-vars, not mounted files)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codeguard.github.auth import _load_private_key


def test_prefers_raw_key_over_path_when_both_set(tmp_path):
    key_file = tmp_path / "key.pem"
    key_file.write_text("FILE_KEY")
    settings = SimpleNamespace(github_private_key="ENV_KEY", github_private_key_path=str(key_file))

    assert _load_private_key(settings) == "ENV_KEY"


def test_falls_back_to_path_when_raw_key_unset(tmp_path):
    key_file = tmp_path / "key.pem"
    key_file.write_text("FILE_KEY")
    settings = SimpleNamespace(github_private_key="", github_private_key_path=str(key_file))

    assert _load_private_key(settings) == "FILE_KEY"


def test_raises_when_neither_is_set():
    settings = SimpleNamespace(github_private_key="", github_private_key_path="")

    with pytest.raises(ValueError):
        _load_private_key(settings)
