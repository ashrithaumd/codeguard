"""PR reviews: changed JS/TS, Go, Java and C# files.

Ingestion fetches them (capped; the rest are listed as not scanned) beside
the Python files, never among them. The worker's prepare_generic runs the
vendored rules, keeps findings on changed lines, triages them, masks the
secrets scan's spans in what goes to the model, and returns the review-state
additions -- nothing for a Python-only PR.
"""

from __future__ import annotations

import random
import string
from unittest.mock import patch

from codeguard.config import RepoConfig, Settings, get_settings
from codeguard.diff.ingest import ingest_pr_diff
from codeguard.diff.models import DiffIngestionResult
from codeguard.tools.gitleaks_runner import SecretScan
from codeguard.worker.main import prepare_generic

JS = "function run(userInput) {\n  return eval(userInput);\n}\n"
JS_PATCH = "@@ -0,0 +1,3 @@\n+function run(userInput) {\n+  return eval(userInput);\n+}\n"


def _pr_file(name, patch_text="@@ -0,0 +1 @@\n+x", additions=1):
    return {"filename": name, "additions": additions, "deletions": 0, "patch": patch_text}


async def _ingest(raw_files, contents, **settings_over):
    base = get_settings().model_dump()
    base.update(settings_over)
    with patch("codeguard.diff.ingest.get_pr_files", return_value=raw_files), \
         patch("codeguard.diff.ingest.get_file_content", side_effect=lambda t, o, r, p, s: contents.get(p)):
        return await ingest_pr_diff("tok", "o", "r", 1, "sha", RepoConfig(), Settings(**base))


async def test_ingestion_fetches_covered_non_python_files_beside_python_not_among_them():
    result = await _ingest([_pr_file("app.py"), _pr_file("web/run.js", JS_PATCH), _pr_file("App.kt")],
                           {"app.py": "x = 1\n", "web/run.js": JS})
    assert list(result.file_contents) == ["app.py"]
    assert result.generic_contents == {"web/run.js": JS} and result.generic_patches == {"web/run.js": JS_PATCH}
    assert [(f.path, f.reason) for f in result.files_filtered] == [("App.kt", "Not covered by any scanner (Kotlin)")]


async def test_files_beyond_the_scan_cap_are_listed_not_dropped():
    raw = [_pr_file(f"src/m{i}.ts") for i in range(4)]
    result = await _ingest(raw, {f"src/m{i}.ts": "export {}\n" for i in range(4)}, generic_scan_files_per_pr=2)
    assert sorted(result.generic_contents) == ["src/m0.ts", "src/m1.ts"]
    assert [(f.path, f.reason) for f in result.files_filtered] == [
        ("src/m2.ts", "not scanned (cap: 2 non-Python files per PR)"),
        ("src/m3.ts", "not scanned (cap: 2 non-Python files per PR)")]


def _diff(**over):
    d = DiffIngestionResult(owner="o", repo="r", pr_number=1, files_seen=1)
    return d.model_copy(update=over)


async def test_prepare_generic_returns_state_for_the_agent_and_nothing_for_python_only():
    empty = await prepare_generic(_diff(), SecretScan(), get_settings())
    assert empty.state == {} and empty.findings == [] and empty.capped == []

    prep = await prepare_generic(_diff(generic_contents={"web/run.js": JS}, generic_patches={"web/run.js": JS_PATCH}),
                                 SecretScan(), get_settings())
    assert list(prep.state["generic_files"]) == ["web/run.js"]
    assert any("eval" in f.rule_id for f in prep.state["generic_findings"]["web/run.js"])
    assert prep.state["generic_scanned"] == ["web/run.js"]
    assert prep.cache_keys and all(k[2] == "security_generic/v2" for k in prep.cache_keys)


async def test_only_findings_on_changed_lines_are_kept():
    """Same rule as Python's (tools/line_filter.py): changed ranges plus a
    3-line margin. The unchanged eval sits well outside it."""
    content = "const a = 1;\n" + "// filler\n" * 10 + JS
    patch_text = "@@ -1,1 +1,1 @@\n-const a = 0;\n+const a = 1;\n"  # eval is unchanged
    prep = await prepare_generic(_diff(generic_contents={"web/run.js": content},
                                       generic_patches={"web/run.js": patch_text}), SecretScan(), get_settings())
    assert prep.state.get("generic_findings", {}) == {} and prep.findings == []


async def test_what_goes_to_the_model_has_the_secret_spans_masked():
    rng = random.Random(4)
    key = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(30))
    content = f'const t = "{key}";\n' + JS
    start = content.splitlines()[0].index(key)
    patch_text = "@@ -0,0 +1,4 @@\n" + "".join(f"+{line}\n" for line in content.splitlines())
    secrets = SecretScan(spans={"web/run.js": [(1, start, start + len(key))]})
    prep = await prepare_generic(_diff(generic_contents={"web/run.js": content},
                                       generic_patches={"web/run.js": patch_text}), secrets, get_settings())
    sent = prep.state["generic_files"]["web/run.js"]
    assert key not in sent and "[redacted]" in sent


async def test_a_credential_finding_line_is_masked_before_the_model():
    content = ("import java.security.MessageDigest;\npublic class Db {\n    void open(String u) throws Exception {\n"
               '        java.sql.DriverManager.getConnection(u, "admin", "Tr0ub4dor-hunter22");\n'
               '        MessageDigest.getInstance("MD5");\n    }\n}\n')
    patch_text = "@@ -0,0 +1,7 @@\n" + "".join(f"+{line}\n" for line in content.splitlines())
    prep = await prepare_generic(_diff(generic_contents={"Db.java": content},
                                       generic_patches={"Db.java": patch_text}), SecretScan(), get_settings())
    sent = prep.state["generic_files"]["Db.java"]
    assert "Tr0ub4dor-hunter22" not in sent


async def test_a_failed_non_python_scan_is_named_for_the_check_summary():
    from codeguard.tools.base import unavailable_finding
    with patch("codeguard.worker.main.run_generic_scanners",
               return_value=[unavailable_finding("semgrep-non-python", "timed out after 60s")]):
        prep = await prepare_generic(_diff(generic_contents={"web/run.js": JS},
                                           generic_patches={"web/run.js": JS_PATCH}), SecretScan(), get_settings())
    assert prep.unavailable == ["semgrep-non-python"] and prep.findings == []


def test_the_check_summary_names_every_scanner_that_did_not_run():
    from codeguard.worker.main import GenericPrep, _summary_tool_findings
    out = _summary_tool_findings([], SecretScan(unavailable=True), GenericPrep(unavailable=["semgrep-non-python"]))
    from codeguard.github.check_summary import unavailable_tools
    assert unavailable_tools(out) == ["gitleaks", "semgrep-non-python"]
    assert _summary_tool_findings([], SecretScan(), GenericPrep()) == []
