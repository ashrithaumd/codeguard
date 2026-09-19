"""Loads a repo's .codeguard.yml — reads from the PR's base branch,
never the head, because PR content is untrusted and must not be able
to edit the policy that governs its own review (see RepoConfig's own
docstring in config.py).
"""

from __future__ import annotations

import logging

import yaml

from codeguard.config import RepoConfig
from codeguard.github.diff import get_file_content

logger = logging.getLogger(__name__)

CONFIG_PATH = ".codeguard.yml"


def load_repo_config(token: str, owner: str, repo: str, base_ref: str) -> RepoConfig:
    """`base_ref` must be the PR's base branch (e.g. "main"), never the
    head branch or a fork — enforced by the caller passing the right
    ref; this function has no way to verify that on its own, which is
    exactly why it's documented so plainly at every layer.

    No .codeguard.yml (the common case) or a YAML file that doesn't
    parse falls back to RepoConfig()'s defaults rather than failing the
    whole review over an optional file.
    """
    try:
        content = get_file_content(token, owner, repo, CONFIG_PATH, ref=base_ref)
    except Exception:
        logger.exception("failed to fetch %s from %s@%s, using defaults", CONFIG_PATH, repo, base_ref)
        return RepoConfig()

    if content is None:
        return RepoConfig()

    try:
        data = yaml.safe_load(content) or {}
    except yaml.YAMLError:
        logger.exception("%s on %s@%s is not valid YAML, using defaults", CONFIG_PATH, repo, base_ref)
        return RepoConfig()

    try:
        return RepoConfig(**data)
    except Exception:
        logger.exception("%s on %s@%s failed validation, using defaults: %r", CONFIG_PATH, repo, base_ref, data)
        return RepoConfig()
