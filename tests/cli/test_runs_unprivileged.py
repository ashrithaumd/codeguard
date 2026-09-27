"""The audit must work without root, and must not need to write to /app.

WHY THIS IS TESTED FROM INSIDE THE PROCESS rather than by inspecting the
Dockerfile: `grep USER Dockerfile` proves the line exists, not that the
image works once it is there. The failures a non-root switch actually
causes are all of the form "something wanted to write somewhere it no
longer can", and they surface at runtime, in one code path, usually the
first time a real repository is audited:

  * a scanner wanting a cache directory under $HOME
  * tiktoken downloading and caching its encoding
  * tempfile.mkdtemp picking a directory the user cannot create in
  * Python trying to write __pycache__ next to an installed module

So these assert the properties the container depends on, and they run in
CI and in the container alike. The Dockerfile is checked too -- a
property nobody enforces is a property that regresses -- but the
Dockerfile check is the weakest test here, not the point of the file.

WHAT ROOT WAS BUYING US: nothing. The audit reads files, runs three
scanners that read files, and writes one report. Running as root meant a
parser vulnerability in Bandit, Semgrep or Ruff -- each of which parses
attacker-authored files -- had the container rather than one unprivileged
user.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


# --- the properties the container relies on ------------------------------


def test_a_writable_temp_directory_exists():
    """run_audit clones into tempfile.mkdtemp. If $TMPDIR is not writable
    by the running user, every audit fails at the clone with a message
    about permissions rather than about the repository."""
    with tempfile.TemporaryDirectory(prefix="codeguard-probe-") as tmp:
        probe = Path(tmp) / "f"
        probe.write_text("ok", encoding="utf-8")
        assert probe.read_text(encoding="utf-8") == "ok"


def test_a_writable_home_exists():
    """Semgrep keeps a cache under $HOME and is not graceful about a
    read-only one. A non-root image that forgets to create and chown a
    home directory leaves HOME pointing at / or at a root-owned path."""
    home = os.environ.get("HOME") or os.path.expanduser("~")
    assert home and home != "/", f"HOME is unusable: {home!r}"
    assert os.access(home, os.W_OK), f"HOME is not writable: {home}"


def test_the_tokenizer_loads_without_a_writable_install_tree():
    """tiktoken fetches and caches an encoding on first use. If it tried to
    cache inside the read-only install tree, every audit would fail on the
    first _count_tokens call -- which happens before any scanner runs, so
    the failure would look like a code bug rather than a permissions one."""
    from codeguard.cli import _count_tokens

    assert _count_tokens("def f(): pass") > 0


def test_an_audit_does_not_need_to_write_into_the_install_tree():
    """/app stays root-owned and read-only to the app user deliberately: a
    process reviewing untrusted code should not be able to modify the code
    reviewing it. This asserts nothing in the audit path depends on
    writing there -- Python skips __pycache__ silently when it cannot
    write, but anything else would not.
    """
    from codeguard.cli import _collect_repo_files, _synthetic_whole_file_patch
    from codeguard.config import RepoConfig

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "a.py").write_text("x = 1\n", encoding="utf-8")
        files, _deps, _patches = _collect_repo_files(root, RepoConfig())

        assert "a.py" in files
        assert _synthetic_whole_file_patch(files["a.py"])


# --- the Dockerfile, as the weakest of these checks ---------------------


def _dockerfile() -> str:
    return (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_the_image_drops_root():
    text = _dockerfile()
    assert re.search(r"^USER\s+\S+", text, re.MULTILINE), (
        "the Dockerfile has no USER instruction, so the worker runs as root"
    )
    assert not re.search(r"^USER\s+root\s*$", text, re.MULTILINE)


def test_nothing_runs_after_the_user_switch_that_needs_root():
    """USER has to come after the installs, and nothing that needs root may
    follow it. apt-get or a global pip install after the switch would fail
    the build; a chown after it silently does nothing useful."""
    text = _dockerfile()
    lines = text.splitlines()
    switch = next(i for i, line in enumerate(lines) if line.startswith("USER "))
    after = "\n".join(lines[switch + 1:])

    for forbidden in ("apt-get", "chown", "useradd", "adduser"):
        assert forbidden not in after, (
            f"{forbidden!r} appears after the USER switch, where it cannot work"
        )


def test_the_user_owns_its_home():
    """The failure this catches: a USER with no home directory created for
    it, which works until the first scanner wants a cache."""
    text = _dockerfile()
    assert "chown" in text, "the non-root user is given nothing it owns"
    assert "ENV HOME=" in text or "--home" in text or "-m " in text, (
        "the non-root user has no home directory"
    )
