"""The structured audit results page.

It was a raw markdown dump. It now renders audits.report_json -- the data
the markdown was rendered FROM (cli.build_report_data) -- with ordinary
autoescaped templates: a severity summary, one card per finding, collapsed
sections for dismissals, skips and technical details, and the raw report
behind a toggle. Never parsed markdown: the report carries text a
repository's authors control.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from codeguard.api import audits as audits_mod

OWNER = "ashrithaumd"
REPO = "codeguard-playground"
VIEWER = "ashrithaumd"


def _report(**over) -> dict:
    data = {
        "version": 1,
        "target": f"https://github.com/{OWNER}/{REPO}",
        "summary": {"files_scanned": 3, "files_ai_aware": 1, "total": 3,
                    "counts": {"critical": 0, "high": 1, "medium": 1, "low": 1},
                    "repo_level": 1, "dismissed": 1, "skipped_test_asserts": 2},
        "incomplete": [],
        "findings": [
            {"severity": "high", "title": "Model output passed to eval()", "file": "assistant.py",
             "start_line": 64, "end_line": 64, "what": "run_untrusted() evals the completion.",
             "why": "A prompt-injected reply becomes code execution.", "fix": "Use an allowlist.",
             "message": "m", "rules": ["llm-output-to-dangerous-sink", "B307"], "source_tool": "ai_aware"},
            {"severity": "medium", "title": "Unpinned model alias", "file": "assistant.py",
             "start_line": 47, "end_line": 47, "what": "Uses -latest.", "why": "", "fix": "",
             "message": "m", "rules": ["llm-unpinned-model-alias"], "source_tool": "ai_aware"},
            {"severity": "low", "title": "Full response logged", "file": "assistant.py",
             "start_line": 81, "end_line": 83, "what": "Logs the response.", "why": "", "fix": "",
             "message": "m", "rules": ["llm-logging-full-prompt-or-response"], "source_tool": "ai_aware"},
        ],
        "repo_level": [{"severity": "medium", "title": "No evals", "message": "No evals/ directory.",
                        "rules": ["eval-hygiene.missing-evals"]}],
        "dismissed": [{"file": "assistant.py", "start_line": 21, "rule_id": "llm-hardcoded-api-key",
                       "reason": "The value is placeholder-shaped."}],
        "skipped_files": [], "verdict_call_failures": [],
        "technical": {"tokens_in": 5756, "tokens_out": 1165, "estimated_cost_usd": 0.0347,
                      "elapsed_s": 29.3, "models": {"ai_aware": "claude-sonnet-x"}},
    }
    data.update(over)
    return data


async def _audit(pool, *, report_json=None, markdown="# CodeGuard audit\n\nraw body\n", status="done"):
    audit_id = uuid.uuid4()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO audits (id, owner, repo, requested_by, private, status, created_at) "
            "VALUES (%s, %s, %s, %s, FALSE, 'running', %s)",
            (audit_id, OWNER, REPO, VIEWER, datetime.now(timezone.utc)),
        )
    await audits_mod.finish_audit(
        pool, audit_id, status=status, report_markdown=markdown, report_json=report_json,
        exit_code=0, tokens_in=5756, tokens_out=1165, estimated_cost_usd=0.0347, duration_s=29.3,
    )
    return audit_id


def _main_view(html: str) -> str:
    """The page with every collapsed <details> section removed -- what a
    reader sees without expanding anything."""
    return re.sub(r"<details.*?</details>", "", html, flags=re.S)


async def test_the_summary_bar_counts_by_severity_and_shows_cost_and_duration(client, pool, as_principal):
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=_report())}").text

    bar = re.search(r'class="sev-summary".*?</div>\s*</div>', page, re.S).group(0)
    for label, n in (("High", 1), ("Medium", 1), ("Low", 1)):
        assert re.search(rf"{label}\s*<b>{n}</b>|<b>{n}</b>\s*{label}", bar), label
    assert "$0.0347" in page and "29.3s" in page


async def test_one_card_per_finding_most_severe_first(client, pool, as_principal):
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=_report())}").text

    findings_panel = page[:page.index("Repository-level")]
    titles = re.findall(r'class="finding-title">([^<]+)<', findings_panel)
    assert titles == ["Model output passed to eval()", "Unpinned model alias", "Full response logged"]
    assert "assistant.py:64" in page
    assert "assistant.py:81–83" in page
    assert "Why it matters" in page and "A prompt-injected reply becomes code execution." in page
    assert "How to fix" in page and "Use an allowlist." in page
    # Both rules of a merged finding, as tags.
    card = page[page.index("Model output passed to eval()"):page.index("Unpinned model alias")]
    assert re.search(r'class="tag rule">\s*llm-output-to-dangerous-sink', card)
    assert re.search(r'class="tag rule">\s*B307', card)


async def test_empty_why_and_fix_are_not_rendered_as_empty_headings(client, pool, as_principal):
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=_report())}").text
    card = page[page.index("Unpinned model alias"):page.index("Full response logged")]
    assert "Why it matters" not in card and "How to fix" not in card


async def test_dismissed_and_technical_details_are_collapsed(client, pool, as_principal):
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=_report())}").text

    assert re.search(r"<details[^>]*>\s*<summary[^>]*>\s*Dismissed by AI \(1\)", page)
    assert "The value is placeholder-shaped." in page
    assert re.search(r"<details[^>]*>\s*<summary[^>]*>\s*Technical details", page)
    main = _main_view(page)
    assert "placeholder-shaped" not in main
    # Internal fields live only in the collapsed technical section.
    assert "Exit code" not in main and not re.search(r"d chars", main)
    assert "Exit code" in page and "claude-sonnet-x" in page


async def test_the_raw_report_is_behind_a_toggle(client, pool, as_principal):
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=_report())}").text
    assert re.search(r"<details[^>]*>\s*<summary[^>]*>\s*View raw report", page)
    assert "raw body" in page and "raw body" not in _main_view(page)


async def test_skipped_test_asserts_and_repo_level_findings_are_shown(client, pool, as_principal):
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=_report())}").text
    assert "2 test asserts" in page
    assert "No evals/ directory." in page
    assert "&lt;repo&gt;:0" not in page and "<repo>:0" not in page


async def test_the_audit_note_appears_exactly_once(client, pool, as_principal):
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=_report())}").text
    assert page.lower().count("no code patches") == 1


async def test_an_audit_from_before_report_json_falls_back_to_the_raw_report(client, pool, as_principal):
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=None)}").text
    assert '<pre class="report">' in page
    assert "raw body" in _main_view(page)
    assert "finding-title" not in page


async def test_finding_text_is_escaped(client, pool, as_principal):
    data = _report()
    data["findings"][0]["what"] = "<script>alert('x')</script>"
    data["findings"][0]["title"] = "<img src=x onerror=alert(1)>"
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=data)}").text
    assert "<script>alert('x')" not in page and "<img src=x" not in page
    assert "&lt;script&gt;" in page


async def test_an_unknown_report_version_falls_back_too(client, pool, as_principal):
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=_report(version=99))}").text
    assert '<pre class="report">' in page and "finding-title" not in page


async def test_a_taint_card_shows_both_locations(client, pool, as_principal):
    data = _report()
    data["findings"][0].update({"start_line": 49, "end_line": 49, "source_line": 44,
                                "flow": "Assigned at line 44, sent to the model at line 49."})
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=data)}").text
    assert "assistant.py:44 → 49" in page


async def test_unreviewed_findings_are_announced_and_badged(client, pool, as_principal):
    data = _report()
    data["summary"]["unreviewed"] = 1
    data["summary"]["verdict_calls_failed"] = 1
    data["findings"][1]["unreviewed"] = True
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=data)}").text

    assert "AI review unavailable for 1 finding(s); shown unreviewed." in page
    card = page[page.index("Unpinned model alias"):page.index("Full response logged")]
    assert ">Unreviewed<" in card
    first = page[page.index("Model output passed to eval()"):page.index("Unpinned model alias")]
    assert ">Unreviewed<" not in first


async def test_no_unreviewed_notice_on_a_clean_audit(client, pool, as_principal):
    as_principal(VIEWER)
    page = client.get(f"/dashboard/audits/{await _audit(pool, report_json=_report())}").text
    assert "AI review unavailable" not in page
