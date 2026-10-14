"""Our own suppressions over the vendored rules (rules_lang/suppress-*.yaml).

GitLab's javascript_react_rule-dangerouslysetinnerhtml fires on every use of
dangerouslySetInnerHTML, sanitized or not, and the model confirmed the
DOMPurify-sanitized near miss in all three eval runs. The vendored rule is
kept byte-exact (rules_vendor/.../MANIFEST.sha256), so the exception lives
in a suppressor rule of ours: where it matches, the vendored finding on that
line is dropped before anything sees it, and the suppressor itself is never
reported. Anything it does not match -- raw input, or a sanitized value that
is computed and then not the one rendered -- is still raised.
"""

from __future__ import annotations

from codeguard.tools.semgrep_runner import run_vendor_rules

RULE = "javascript_react_rule-dangerouslysetinnerhtml"

FILES = {
    "inline.tsx": (
        'import DOMPurify from "dompurify";\n'
        "export const A = ({ html }: { html: string }) => (\n"
        "  <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />\n"
        ");\n"
    ),
    "via_const.tsx": (
        'import DOMPurify from "dompurify";\n'
        "export function B({ body }: { body: string }) {\n"
        "  const clean = DOMPurify.sanitize(body);\n"
        "  return <div dangerouslySetInnerHTML={{ __html: clean }} />;\n"
        "}\n"
    ),
    "create_element.js": (
        'import React from "react";\n'
        'import DOMPurify from "dompurify";\n'
        "export function C(props) {\n"
        '  return React.createElement("div", { dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(props.html) } });\n'
        "}\n"
    ),
    "raw.tsx": (
        "export const D = ({ html }: { html: string }) => (\n"
        "  <div dangerouslySetInnerHTML={{ __html: html }} />\n"
        ");\n"
    ),
    "sanitized_but_raw_rendered.tsx": (
        'import DOMPurify from "dompurify";\n'
        "export function E({ body }: { body: string }) {\n"
        "  const clean = DOMPurify.sanitize(body);\n"
        "  console.log(clean.length);\n"
        "  return <div dangerouslySetInnerHTML={{ __html: body }} />;\n"
        "}\n"
    ),
}


def _by_file():
    found: dict[str, list[str]] = {}
    for f in run_vendor_rules(FILES):
        found.setdefault(f.file, []).append(f.rule_id)
    return found


def test_sanitized_html_is_not_raised_and_unsanitized_still_is():
    found = _by_file()
    # Sanitized at the point of use, through a const, and in createElement form.
    for path in ("inline.tsx", "via_const.tsx", "create_element.js"):
        assert RULE not in found.get(path, []), path
    # Raw input, and a sanitized value that is not the one rendered.
    for path in ("raw.tsx", "sanitized_but_raw_rendered.tsx"):
        assert RULE in found.get(path, []), path
    # A suppressor is a filter, never a finding.
    assert not any(r.startswith("codeguard-suppress-") for rules in found.values() for r in rules)


def test_every_suppressor_rule_is_mapped_to_the_rule_it_suppresses():
    from pathlib import Path

    import yaml

    from codeguard.tools.semgrep_runner import OWN_LANG_RULES_DIR, SUPPRESSIONS, SUPPRESSOR_PREFIX

    declared = {}
    for path in Path(OWN_LANG_RULES_DIR).glob("suppress-*.yaml"):
        for rule in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
            assert rule["id"].startswith(SUPPRESSOR_PREFIX), rule["id"]
            declared[rule["id"]] = rule["metadata"]["suppresses"]
    assert declared == SUPPRESSIONS
