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

# Semgrep is pinned at 1.95.0 (later releases drop the data-flow traces the
# flow note reads) and must not touch the network. --metrics=off does NOT
# stop its new-version check: measured, a plain scan with --metrics=off
# makes 4 connection attempts to semgrep.dev. SEMGREP_ENABLE_VERSION_CHECK=0
# stops them; the image sets it and so does the runner.
#
# Proved, not assumed, three ways, all with --network none and a
# sitecustomize in the Semgrep process that records and refuses every
# hostname lookup and connection:
#   1. the guard must load, and must CATCH the version check when it is not
#      disabled -- a guard that catches nothing proves nothing;
#   2. a scan through our own runner, with the image's environment, makes
#      zero attempts and really scans (a probe rule must fire);
#   3. the same with the version-check variables removed from the
#      environment, so only the runner's own setting stands between Semgrep
#      and the network.
# The guard is written with chr(10), not backslash escapes, so no layer of
# shell quoting can corrupt it into a file Python silently fails to load.
echo "checking semgrep is pinned and attempts no network connection"
SEMGREP_PROBE='
import os, pathlib, subprocess, sys
NL = chr(10)
guard = pathlib.Path("/tmp/netguard"); guard.mkdir(exist_ok=True)
(guard / "sitecustomize.py").write_text(NL.join([
    "import socket",
    "open(\"/tmp/guard_loaded.log\", \"a\").write(\"loaded\" + chr(10))",
    "def _deny(*a, **k):",
    "    open(\"/tmp/net_attempts.log\", \"a\").write(repr(a[:1]) + chr(10))",
    "    raise OSError(\"network disabled by smoke test\")",
    "socket.socket.connect = _deny",
    "socket.create_connection = _deny",
    "socket.getaddrinfo = _deny",
    "",
]))
LOADED, ATTEMPTS = pathlib.Path("/tmp/guard_loaded.log"), pathlib.Path("/tmp/net_attempts.log")
def reset():
    LOADED.unlink(missing_ok=True); ATTEMPTS.unlink(missing_ok=True)
def attempts():
    return ATTEMPTS.read_text().strip().splitlines() if ATTEMPTS.exists() else []
os.environ["PYTHONPATH"] = str(guard)

version = subprocess.run([os.environ["SEMGREP_BIN"], "--version"], capture_output=True, text=True,
                         env={**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0"}).stdout.strip().splitlines()[-1]
if not os.environ.get("SEMGREP_BIN", "").startswith("/opt/semgrep/"):
    sys.exit("=== FAIL: SEMGREP_BIN is %r, expected /opt/semgrep/... ===" % os.environ.get("SEMGREP_BIN"))
if version != "1.95.0":
    sys.exit("=== FAIL: semgrep is %r, expected 1.95.0 ===" % version)

if os.environ.get("CONTROL") == "1":
    reset()
    bare = {k: v for k, v in os.environ.items() if k not in ("SEMGREP_ENABLE_VERSION_CHECK", "SEMGREP_SEND_METRICS")}
    subprocess.run([os.environ["SEMGREP_BIN"], "--version"], env=bare, capture_output=True)
    if not LOADED.exists():
        sys.exit("=== FAIL: the network guard did not load in the semgrep process ===")
    if not attempts():
        sys.exit("=== FAIL: the guard caught nothing with the version check enabled; it would prove nothing ===")
    print("=== OK: control -- with the version check enabled the guard catches %d attempt(s) to %s ===" % (len(attempts()), attempts()[0]))

reset()
from codeguard.tools.semgrep_runner import run_semgrep
probe = {"probe.py": NL.join(["import anthropic", "client = anthropic.Anthropic()",
                               "client.messages.create(model=\"claude-3-5-sonnet-latest\", max_tokens=10, messages=[])", ""])}
findings = run_semgrep(probe)
if not LOADED.exists():
    sys.exit("=== FAIL: the network guard did not load in the semgrep process ===")
if attempts():
    sys.exit("=== FAIL: semgrep attempted network connections: %s ===" % attempts())
if not any("unpinned-model-alias" in f.rule_id for f in findings):
    sys.exit("=== FAIL: the probe rule did not fire; the scan did not really run ===")
print("=== OK: semgrep %s via the runner, scan ran, 0 network attempts (image env: %s) ===" % (
    version, os.environ.get("SEMGREP_ENABLE_VERSION_CHECK", "removed")))

# The vendored GitLab rules and our own rules_lang/, in the same offline run.
reset()
from codeguard.tools.semgrep_runner import run_vendor_rules
lang = {"web/run.js": NL.join(["function run(userInput) {", "  return eval(userInput);", "}", ""]),
        "client/http.go": NL.join(["package client", "", "import \"crypto/tls\"", "",
                                   "func C() *tls.Config {", "\treturn &tls.Config{InsecureSkipVerify: true}", "}", ""])}
rules = {f.rule_id for f in run_vendor_rules(lang)}
if attempts():
    sys.exit("=== FAIL: the vendored-rules run attempted network connections: %s ===" % attempts())
if "javascript_eval_rule-eval-with-expression" not in rules or "codeguard-go-tls-insecure-skip-verify" not in rules:
    sys.exit("=== FAIL: vendored or own language rules did not fire: %s ===" % sorted(rules))
print("=== OK: vendored + own language rules ran offline, both probes fired ===")
'
docker run --rm --network none -e CONTROL=1 "$IMAGE" python -c "$SEMGREP_PROBE"
docker run --rm --network none --entrypoint env "$IMAGE" -u SEMGREP_ENABLE_VERSION_CHECK -u SEMGREP_SEND_METRICS python -c "$SEMGREP_PROBE"


# Gitleaks: pinned (verified by sha256 at build) and offline. A key is
# generated inside the container, scanned through our own runner, and must
# be found -- and must appear NOWHERE in what the runner returns. Nothing
# is printed but counts.
echo "checking gitleaks is pinned, runs offline, and never returns a secret"
GITLEAKS_PROBE='
import json, secrets, string, sys
from codeguard.config import RepoConfig
from codeguard.tools.gitleaks_runner import scan_secrets
import subprocess
version = subprocess.run(["gitleaks", "version"], capture_output=True, text=True).stdout.strip()
if version != "8.30.1":
    sys.exit("=== FAIL: gitleaks is %r, expected 8.30.1 ===" % version)
key = "ghp_" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
scan = scan_secrets({"config/app.yml": "app:" + chr(10) + "  token: " + chr(34) + key + chr(34) + chr(10)}, RepoConfig())
if scan.unavailable or len(scan.findings) != 1:
    sys.exit("=== FAIL: expected one finding, got %d (unavailable=%s) ===" % (len(scan.findings), scan.unavailable))
kept = repr(scan) + json.dumps([f.model_dump() for f in scan.findings], default=str)
if key in kept or key[4:20] in kept:
    sys.exit("=== FAIL: the secret value appears in the scan result ===")
print("=== OK: gitleaks %s offline, 1 finding, value absent from the result ===" % version)
'
docker run --rm --network none "$IMAGE" python -c "$GITLEAKS_PROBE"


# zizmor: pinned (installed by hash at build), offline. A Rust binary, so the
# Python socket guard above cannot reach inside it; the proof is that it runs
# and finds the injection in a container with no network at all, with every
# GitHub token variable set (the runner must strip them).
echo "checking zizmor is pinned and finds template injection with no network"
ZIZMOR_PROBE='
import os, subprocess, sys
NL = chr(10)
version = subprocess.run([os.environ["ZIZMOR_BIN"], "--version"], capture_output=True, text=True).stdout.strip()
if version != "zizmor 1.30.1":
    sys.exit("=== FAIL: zizmor is %r, expected zizmor 1.30.1 ===" % version)
from codeguard.tools.zizmor_runner import run_zizmor
wf = NL.join(["on:", "  issues:", "    types: [opened]", "permissions: {}", "jobs:", "  a:", "    runs-on: ubuntu-latest",
              "    steps:", "      - run: echo \"${{ github.event.issue.title }}\"", ""])
findings = run_zizmor({".github/workflows/ci.yml": wf})
if [f for f in findings if f.rule_id == "internal.tool_unavailable"]:
    sys.exit("=== FAIL: zizmor did not run offline: %s ===" % findings)
if not any(f.rule_id == "template-injection" for f in findings):
    sys.exit("=== FAIL: template-injection not found: %s ===" % sorted(f.rule_id for f in findings))
print("=== OK: %s offline, template-injection found ===" % version)
'
docker run --rm --network none -e GH_TOKEN=smoke -e GITHUB_TOKEN=smoke "$IMAGE" python -c "$ZIZMOR_PROBE"

# The tokenizer must already be IN the image. tiktoken downloads
# cl100k_base on first use and caches it; a container that has to fetch it
# at runtime fails its first audit on any network that blocks the download,
# and pays the fetch on every cold start. --network none makes "bundled"
# something this proves rather than assumes.
echo "checking the tiktoken encoding loads with no network"
docker run --rm --network none \
    "$IMAGE" python -c "import tiktoken; tiktoken.get_encoding('cl100k_base'); print('=== OK: cl100k_base is bundled ===')"
