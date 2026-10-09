"""The review_impact node and the summary's "Callers outside this diff".

Signature breaks are deterministic: a HIGH finding on the changed def's
line (in the diff, so it can be an inline comment) naming the callers, and
a line per caller in the summary, linked at the PR head. Behaviour is the
model's: ONE call per PR, only for functions whose body changed, given the
before/after source and the chosen call sites, asked which callers rely on
what changed. Out-of-diff callers can only be in the summary: GitHub
refuses inline comments outside the diff.

Mocked model throughout. No live calls.
"""

from __future__ import annotations

import difflib
from unittest.mock import patch

from codeguard.config import RepoConfig
from codeguard.pipeline.impact import analyze
from codeguard.pipeline.impact_review import IMPACT_SECTION_TITLE, render_impact_section, review_impact
from codeguard.pipeline.llm_call import AgentCallResult
from codeguard.severity import Severity

HEAD = "f" * 40

CHARGE_BASE = 'def charge(amount, currency):\n    return {"amount": amount, "currency": currency}\n'
CHARGE_HEAD = ('def charge(amount, currency, *, idempotency_key):\n'
               '    return {"amount": amount, "currency": currency, "key": idempotency_key}\n')
CALLER = "from billing.charge import charge\n\n\ndef checkout(total):\n    return charge(total, 'usd')\n"


def _patch(base, head, path):
    return "".join(difflib.unified_diff(base.splitlines(True), head.splitlines(True), f"a/{path}", f"b/{path}"))


def _report(base=CHARGE_BASE, head=CHARGE_HEAD, callers=None, extra_patches=None):
    head_files = {"billing/charge.py": head, **(callers or {"api/checkout.py": CALLER})}
    patches = {"billing/charge.py": _patch(base, head, "billing/charge.py"), **(extra_patches or {})}
    return analyze(head_files=head_files, base_files={"billing/charge.py": base}, patches=patches,
                   per_symbol=5, per_pr=15)


def _state(report, **over):
    state = {"owner": "acme", "repo": "shop", "pr_number": 4, "head_sha": HEAD,
             "repo_config": RepoConfig(), "impact_report": report}
    state.update(over)
    return state


def _model(text, **usage):
    return AgentCallResult(raw_text=text, tokens_in=usage.get("tin", 900), tokens_out=usage.get("tout", 80),
                           estimated_cost_usd=usage.get("cost", 0.002), latency_s=0.1)


# --------------------------------------------------------------------------
# The node
# --------------------------------------------------------------------------

def test_no_report_means_no_work_and_no_call():
    with patch("codeguard.pipeline.impact_review.call_agent") as call:
        assert review_impact(_state(None)) == {}
        assert review_impact({k: v for k, v in _state(None).items() if k != "impact_report"}) == {}
    call.assert_not_called()


def test_a_signature_break_is_a_high_finding_on_the_def_line_naming_the_caller():
    with patch("codeguard.pipeline.impact_review.call_agent", return_value=_model("[]")):
        out = review_impact(_state(_report()))
    [finding] = out["findings"]
    assert (finding.file, finding.start_line, finding.severity) == ("billing/charge.py", 1, Severity.HIGH)
    assert finding.rule_id == "impact.signature" and finding.source_tool == "impact"
    assert "api/checkout.py:5" in finding.message
    assert "missing required keyword argument 'idempotency_key'" in finding.message
    assert out["impact_callers"] == [{
        "path": "api/checkout.py", "line": 5, "qualname": "charge", "kind": "signature",
        "note": "missing required keyword argument 'idempotency_key'", "in_diff": False}]


def test_a_break_on_a_line_this_pr_changed_is_also_a_finding_at_the_call():
    caller_base = "from billing.charge import charge\ncharge(1, 'eur', idempotency_key='k')\n"
    caller_head = "from billing.charge import charge\ncharge(1, 'usd')\n"
    report = _report(callers={"api/x.py": caller_head},
                     extra_patches={"api/x.py": _patch(caller_base, caller_head, "api/x.py")})
    with patch("codeguard.pipeline.impact_review.call_agent", return_value=_model("[]")):
        out = review_impact(_state(report))
    assert sorted((f.file, f.start_line) for f in out["findings"]) == [("api/x.py", 2), ("billing/charge.py", 1)]


def test_callers_of_a_removed_function_are_listed_with_no_def_line_finding():
    base = CHARGE_BASE + "\n\ndef refund(amount):\n    return -amount\n"
    report = _report(base=base, head=CHARGE_BASE,
                     callers={"r.py": "from billing.charge import refund\nrefund(3)\n"})
    out = review_impact(_state(report))
    assert out.get("findings", []) == []
    assert out["impact_callers"][0]["note"] == "calls 'refund', which this change removes"


def test_a_signature_only_change_makes_no_model_call():
    head = CHARGE_BASE.replace("(amount, currency)", "(amount, currency, note=None)")
    with patch("codeguard.pipeline.impact_review.call_agent") as call:
        review_impact(_state(_report(head=head, callers={"a.py": "from billing.charge import charge\ncharge(1, 'usd')\n"})))
    call.assert_not_called()


BODY_HEAD = 'def charge(amount, currency):\n    if amount <= 0:\n        return None\n    return {"amount": amount, "currency": currency}\n'
BODY_CALLER = "from billing.charge import charge\n\n\ndef total(x):\n    return charge(x, 'usd')['amount']\n"


def test_a_body_change_makes_one_call_with_before_after_and_the_sites():
    report = _report(head=BODY_HEAD, callers={"api/sum.py": BODY_CALLER, "api/other.py": BODY_CALLER})
    reply = ('[{"site": "api/sum.py:5", "symbol": "charge", "concern": "Indexes the result, which is now None '
             'for a non-positive amount."}, {"site": "nowhere.py:1", "symbol": "charge", "concern": "made up"}]')
    with patch("codeguard.pipeline.impact_review.call_agent", return_value=_model(reply)) as call:
        out = review_impact(_state(report))

    call.assert_called_once()
    kwargs = call.call_args.kwargs
    assert kwargs["agent"] == "impact" and kwargs["temperature"] == 0
    content = kwargs["user_content"]
    assert "return None" in content and 'return {"amount"' in content
    assert "api/sum.py:5" in content and "api/other.py:5" in content
    assert out["impact_callers"] == [{
        "path": "api/sum.py", "line": 5, "qualname": "charge", "kind": "behavior",
        "note": "Indexes the result, which is now None for a non-positive amount.", "in_diff": False}]
    assert (out["tokens_in"], out["tokens_out"], out["estimated_cost_usd"]) == (900, 80, 0.002)


def test_the_extra_context_is_capped():
    callers = {f"api/m{i}.py": BODY_CALLER + ("# pad\n" * 400) for i in range(20)}
    with patch("codeguard.pipeline.impact_review.call_agent", return_value=_model("[]")) as call, \
         patch("codeguard.pipeline.impact_review.MAX_CONTEXT_CHARS", 3000):
        review_impact(_state(_report(head=BODY_HEAD, callers=callers)))
    assert len(call.call_args.kwargs["user_content"]) <= 3000 + 200


def test_a_failed_call_is_noted_and_the_signature_part_still_stands():
    failed = AgentCallResult(raw_text=None, error="timeout", latency_s=30.0)
    report = _report(head=BODY_HEAD.replace("(amount, currency)", "(amount, currency, *, key)"),
                     callers={"api/sum.py": BODY_CALLER})
    with patch("codeguard.pipeline.impact_review.call_agent", return_value=failed):
        out = review_impact(_state(report))
    assert [c["kind"] for c in out["impact_callers"]] == ["signature"]
    assert out["impact_notes"] == ["behavior check unavailable (timeout)"]


# --------------------------------------------------------------------------
# The summary section
# --------------------------------------------------------------------------

def _section(report, callers, notes=()):
    return "\n".join(render_impact_section(_state(report, impact_callers=callers, impact_notes=list(notes))))


def test_the_section_links_each_caller_at_the_head_and_tags_the_kind():
    report = _report()
    text = _section(report, [
        {"path": "api/checkout.py", "line": 5, "qualname": "charge", "kind": "signature",
         "note": "missing required keyword argument 'idempotency_key'", "in_diff": False},
        {"path": "api/sum.py", "line": 9, "qualname": "charge", "kind": "behavior",
         "note": "Indexes the result.", "in_diff": False},
    ])
    assert IMPACT_SECTION_TITLE in text
    assert f"(https://github.com/acme/shop/blob/{HEAD}/api/checkout.py#L5)" in text
    assert "signature" in text and "behavior" in text and "Indexes the result." in text


def test_callers_inside_the_diff_are_not_repeated_in_the_section():
    text = _section(_report(), [{"path": "a.py", "line": 2, "qualname": "charge", "kind": "signature",
                                 "note": "x", "in_diff": True}])
    assert "a.py" not in text


def test_model_text_is_escaped_for_github():
    text = _section(_report(), [{"path": "a.py", "line": 2, "qualname": "charge", "kind": "behavior",
                                 "note": "@everyone <img src=x> [click](http://evil)", "in_diff": False}])
    assert "@everyone" not in text and "<img" not in text


def test_omitted_and_dynamic_counts_are_said_not_hidden():
    report = _report()
    report.omitted, report.dynamic_refs = 12, {"charge": 3}
    text = _section(report, [])
    assert "12 more call site(s) not shown" in text
    assert "3 dynamic reference(s)" in text and "not analysed" in text


def test_nothing_to_say_renders_nothing():
    report = _report(callers={"api/fine.py": "from billing.charge import charge\ncharge(1, 'usd', idempotency_key='k')\n"})
    assert render_impact_section(_state(report, impact_callers=[], impact_notes=[])) == []


def test_a_skipped_analysis_says_why():
    text = "\n".join(render_impact_section(_state(None, impact_notes=["skipped: repository too large"])))
    assert "Impact analysis skipped: repository too large" in text


# --------------------------------------------------------------------------
# Regression: the same caller reported twice (live on playground #11)
# --------------------------------------------------------------------------
#
# F1 shape: total() gains a required keyword AND its body changes, and the
# unchanged caller checkout.py:8 breaks. The signature check flagged it,
# the call site still went to the model as behaviour context, and the model
# restated the missing argument -- so the summary listed checkout.py:8 twice
# and the eval's behaviour precision halved.

F1_BASE = "def total(amount, tax_rate):\n    return round(amount * (1 + tax_rate), 2)\n"
F1_HEAD = ("def total(amount, tax_rate, *, currency):\n"
           "    return {\"amount\": round(amount * (1 + tax_rate), 2), \"currency\": currency}\n")
F1_CALLER = "from pricing import total\n\n\ndef checkout(cart):\n    subtotal = sum(cart.values())\n    return total(subtotal, 0.08)\n"


def _f1_report(extra_callers=None):
    head_files = {"pricing.py": F1_HEAD, "checkout.py": F1_CALLER, **(extra_callers or {})}
    return analyze(head_files=head_files, base_files={"pricing.py": F1_BASE},
                   patches={"pricing.py": _patch(F1_BASE, F1_HEAD, "pricing.py")}, per_symbol=5, per_pr=15)


def test_a_caller_flagged_for_its_signature_is_listed_once():
    reply = ('[{"site": "checkout.py:6", "symbol": "total", "concern": "The call is missing the required '
             'keyword-only argument currency and expects a number back."}]')
    with patch("codeguard.pipeline.impact_review.call_agent", return_value=_model(reply)):
        out = review_impact(_state(_f1_report()))
    assert [(c["path"], c["line"], c["kind"]) for c in out["impact_callers"]] == [("checkout.py", 6, "signature")]


def test_the_model_is_told_which_callers_are_already_reported():
    with patch("codeguard.pipeline.impact_review.call_agent", return_value=_model("[]")) as call:
        review_impact(_state(_f1_report()))
    content = call.call_args.kwargs["user_content"]
    assert "checkout.py:6 (resolved; already reported: missing required keyword argument 'currency')" in content
    assert "already reported" in call.call_args.kwargs["system_prompt"]


def test_a_behaviour_concern_on_another_caller_is_still_kept():
    other = "from pricing import total\n\n\ndef label(x):\n    return f'{total(x, 0.1, currency=\"usd\"):.2f}'\n"
    reply = ('[{"site": "checkout.py:6", "symbol": "total", "concern": "missing currency"}, '
             '{"site": "fmt.py:5", "symbol": "total", "concern": "Formats the result as a float, but total now returns a dict."}]')
    with patch("codeguard.pipeline.impact_review.call_agent", return_value=_model(reply)):
        out = review_impact(_state(_f1_report({"fmt.py": other})))
    assert [(c["path"], c["line"], c["kind"]) for c in out["impact_callers"]] == [
        ("checkout.py", 6, "signature"), ("fmt.py", 5, "behavior")]


def test_two_behaviour_concerns_on_one_line_are_one_entry():
    other = "from pricing import total\n\n\ndef label(x):\n    return f'{total(x, 0.1, currency=\"usd\"):.2f}'\n"
    reply = ('[{"site": "fmt.py:5", "symbol": "total", "concern": "Formats a dict as a float."}, '
             '{"site": "fmt.py:5", "symbol": "total", "concern": "Same line, said again."}]')
    with patch("codeguard.pipeline.impact_review.call_agent", return_value=_model(reply)):
        out = review_impact(_state(_f1_report({"fmt.py": other})))
    assert [(c["path"], c["line"]) for c in out["impact_callers"] if c["kind"] == "behavior"] == [("fmt.py", 5)]
