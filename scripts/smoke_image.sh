#!/usr/bin/env bash
# Run one audit inside the BUILT IMAGE, with NO BIND MOUNT, and assert every
# scanner actually ran.
#
# WHY THIS EXISTS. ruff was silently missing from every audit in production
# for a whole deployment. It writes its cache to the current working
# directory; the worker's is /app, which is root-owned and read-only to the
# non-root user on purpose. In Azure that failed:
#
#   error: Failed to initialize cache at /app/.ruff_cache:
#          Permission denied (os error 13)
#
# and empty stdout became "ruff unavailable".
#
# IT PASSED EVERY LOCAL CHECK, including a real container audit run
# specifically to verify the non-root switch. docker compose bind-mounts the
# repository over /app, and that mount is WRITABLE, so ruff's cache
# succeeded locally and failed in production. The local container and the
# deployed container differed in exactly the property under test.
#
# So this script deliberately does what compose does not:
#   * no volume of any kind, so /app is the image's own read-only copy
#   * the image's own USER, so the permissions are the deployed ones
#   * a repository cloned into a temp dir, as an audit really does
#
# It asserts the absence of the "did not run" warning that
# codeguard/cli.py's _incompleteness() emits. That warning is the general
# check -- it fires for any unavailable scanner, not just ruff -- so this
# catches the next permissions bug of this shape, whichever tool it hits.
#
# NO MODEL CALL, AND NO SPEND. The target is a small local tree written
# inside the container, and ANTHROPIC_API_KEY is deliberately a non-key: any
# verdict call fails with 401 before it can cost anything. The scanners are
# the part under test, and the verdict agents only ever review what the
# scanners produce, so their failing changes nothing here.
#
# Network is LEFT ON, reluctantly, because it is currently required: tiktoken
# downloads cl100k_base on first use and the image ships no cached copy, so
# `docker run --network none` dies at import with a DNS failure. That is a
# separate fragility -- every container start depends on reaching
# openaipublic.blob.core.windows.net -- and baking the encoding in at build
# time would let this run with no network at all. Recorded rather than fixed
# here.
#
# Usage:  scripts/smoke_image.sh [image-ref]
# Default image: codeguard-worker:latest, i.e. whatever compose last built.
set -euo pipefail

IMAGE="${1:-codeguard-worker:latest}"

echo "smoke-testing $IMAGE with no bind mount, as the image's own user"

# A tree with one finding per scanner, so "every scanner ran" is observable
# from the report rather than inferred:
#   bandit   -> B608, a string-formatted SQL query
#   ruff     -> F401, an unused import
#   semgrep  -> only fires on LLM-integration code, so it is checked via the
#               warning line rather than by a finding of its own
PROBE='
import os, subprocess, sys, tempfile
root = tempfile.mkdtemp(prefix="smoke-")
open(os.path.join(root, "app.py"), "w").write(
    "import os\n"
    "import sqlite3\n"
    "\n"
    "def get(cursor, email):\n"
    "    cursor.execute(\"SELECT * FROM users WHERE email = %s\" % email)\n"
    "    return cursor.fetchone()\n"
)
out = os.path.join(tempfile.mkdtemp(), "report.md")
proc = subprocess.run(
    [sys.executable, "-m", "codeguard.cli", "audit", root, "--output", out],
    capture_output=True, text=True,
)
sys.stderr.write(proc.stderr)
report = open(out, encoding="utf-8").read() if os.path.exists(out) else ""

print("=== cwd and its writability, the property that broke ruff ===")
print("cwd:", os.getcwd(), "writable:", os.access(os.getcwd(), os.W_OK))
print("uid:", os.getuid())

failed = []
if "did not run" in report:
    for line in report.splitlines():
        if "did not run" in line:
            failed.append(line.strip())
if proc.returncode != 0:
    failed.append("codeguard audit exited %d" % proc.returncode)
for want in ("B608", "F401"):
    if want not in report:
        failed.append("no %s finding: the scanner that owns it produced nothing" % want)

if failed:
    print("=== FAIL ===")
    for line in failed:
        print(" ", line)
    sys.exit(1)
print("=== OK: every scanner ran, and B608 and F401 are both present ===")
'

# No -v of any kind: that is the whole point. No --entrypoint or --user
# override either, so the image's own USER applies and the permissions are
# the deployed ones.
docker run --rm     -e ANTHROPIC_API_KEY=smoke-test-deliberately-not-a-real-key     "$IMAGE" python -c "$PROBE"

# The tokenizer must already be IN the image. tiktoken downloads
# cl100k_base on first use and caches it; a container that has to fetch it
# at runtime fails its first audit on any network that blocks the download,
# and pays the fetch on every cold start. --network none makes "bundled"
# something this proves rather than assumes.
echo "checking the tiktoken encoding loads with no network"
docker run --rm --network none \
    "$IMAGE" python -c "import tiktoken; tiktoken.get_encoding('cl100k_base'); print('=== OK: cl100k_base is bundled ===')"
