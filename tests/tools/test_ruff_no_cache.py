"""ruff must not need a writable working directory.

THE DEFECT THIS REPRODUCES
--------------------------
The non-root worker leaves /app root-owned and read-only to uid 10001, on
purpose: a process reviewing untrusted code should not be able to modify the
code reviewing it. ruff writes its cache into the CURRENT WORKING DIRECTORY,
which for the worker is /app. Measured inside the deployed container:

    cwd /app
    cwd writable False
    error: Failed to initialize cache at /app/.ruff_cache:
           Permission denied (os error 13)
    returncode 2, stdout ''

Empty stdout means json.loads raises, which run_tool_on_pr reports as
"ruff unavailable: Expecting value: line 1 column 1 (char 0)" -- so a whole
scanner was silently missing from every audit in production.

IT PASSED LOCALLY, which is why only a real deployment caught it: docker
compose bind-mounts the repository over /app, and that mount is writable, so
ruff's cache succeeded on a developer machine and failed in Azure.

--no-cache rather than a writable cache directory. The cache buys nothing
here: every audit and every review scans a FRESH temporary directory, so no
run can ever hit a cache entry left by another. Pointing RUFF_CACHE_DIR at
/tmp would also work, but it is an environment variable that a future
deployment can drop, and the failure it causes is silent.

Step 12 is what made this visible at all: the audit report opened with
"ruff did not run, so the rules that tool owns were never applied to any
file". Before that, the finding count would simply have been lower.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile

from codeguard.tools.ruff_runner import _build_cmd, run_ruff


def test_the_command_disables_the_cache():
    cmd = _build_cmd("/some/tmp/dir")
    assert "--no-cache" in cmd, (
        "ruff writes its cache to the cwd, which is read-only in the worker"
    )


def test_ruff_runs_with_a_read_only_working_directory():
    """The property, exercised rather than asserted about a flag.

    Runs the real command from a directory this process cannot write to, the
    way the worker does. Without --no-cache this exits 2 with empty stdout.
    """
    target = tempfile.mkdtemp()
    with open(os.path.join(target, "t.py"), "w", encoding="utf-8") as handle:
        handle.write("import os\n")  # unused import: ruff should flag it

    # A directory owned by root and not writable by anyone else. /proc is
    # guaranteed to exist and to be unwritable, and running from it is a
    # faithful stand-in for the worker's read-only /app.
    proc = subprocess.run(
        _build_cmd(target), capture_output=True, text=True, cwd="/proc", timeout=60,
    )

    assert proc.returncode == 0, proc.stderr
    assert "ruff_cache" not in proc.stderr
    parsed = json.loads(proc.stdout)  # the step that used to raise
    assert any(r.get("code") == "F401" for r in parsed), parsed


def test_findings_still_come_back_through_the_runner():
    """The precision guard: disabling the cache must not disable the tool."""
    findings = run_ruff({"t.py": "import os\n"})

    assert findings, "ruff produced no findings at all"
    assert all(f.source_tool == "ruff" for f in findings)
    assert any(f.rule_id == "F401" for f in findings)
