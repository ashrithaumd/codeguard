"""Impact analysis, the pure part (codeguard/pipeline/impact.py).

For each function or class a PR changes, find its call sites elsewhere in
the repository (AST, Python only) and flag the callers that no longer fit
the new signature. No network, no model: these are the deterministic
checks, and they never flag a call they could not check.
"""

from __future__ import annotations

import difflib
import textwrap

from codeguard.pipeline.impact import (
    added_lines,
    analyze,
    changed_symbols,
    find_call_sites,
    select_call_sites,
)


def _src(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def _patch(base: str, head: str, path: str = "f.py") -> str:
    return "".join(difflib.unified_diff(
        base.splitlines(True), head.splitlines(True), f"a/{path}", f"b/{path}", n=3))


CHARGE_BASE = _src('''
    def charge(amount, currency):
        return {"amount": amount, "currency": currency}


    def refund(amount):
        return -amount
''')

CHARGE_HEAD = _src('''
    def charge(amount, currency, *, idempotency_key):
        return {"amount": amount, "currency": currency, "key": idempotency_key}


    def refund(amount):
        return -amount
''')


def _symbols(base=CHARGE_BASE, head=CHARGE_HEAD, path="billing/charge.py"):
    return changed_symbols(path, base, head)


# --------------------------------------------------------------------------
# What changed
# --------------------------------------------------------------------------

def test_added_lines_are_head_line_numbers():
    assert added_lines(_patch(CHARGE_BASE, CHARGE_HEAD)) == {1, 2}


def test_a_signature_change_is_a_changed_symbol_and_an_untouched_one_is_not():
    [sym] = _symbols()
    assert (sym.qualname, sym.module, sym.kind, sym.line) == ("charge", "billing.charge", "function", 1)
    assert sym.signature_changed and sym.body_changed


def test_a_body_only_change_keeps_the_signature():
    head = CHARGE_BASE.replace("return -amount", "return 0 - abs(amount)")
    [sym] = _symbols(head=head)
    assert sym.qualname == "refund" and not sym.signature_changed and sym.body_changed


def test_a_deletion_only_edit_inside_a_function_is_a_change():
    """Compared by AST, not by added line numbers: a hunk that only
    deletes lines adds nothing on the head side."""
    base = "def f(a):\n    a += 1\n    return a\n"
    head = "def f(a):\n    return a\n"
    [sym] = _symbols(base, head, "m.py")
    assert sym.qualname == "f" and sym.body_changed and not sym.signature_changed


def test_a_removed_function_is_a_changed_symbol():
    head = CHARGE_BASE.split("\n\n\ndef refund")[0] + "\n"
    [sym] = _symbols(head=head)
    assert (sym.qualname, sym.kind) == ("refund", "removed")


def test_a_method_and_a_constructor():
    base = _src('''
        class Client:
            def __init__(self, url):
                self.url = url

            def send(self, body):
                return body
    ''')
    head = base.replace("def __init__(self, url):", "def __init__(self, url, token):") \
               .replace("def send(self, body):", "def send(self, body, *, retries):")
    found = {s.qualname: s for s in _symbols(base, head, "net/client.py")}
    assert set(found) == {"Client", "Client.send"}
    assert found["Client"].kind == "class" and found["Client"].signature_changed
    assert found["Client.send"].kind == "method"


# --------------------------------------------------------------------------
# Where it is called from
# --------------------------------------------------------------------------

def _sites(files, symbols=None):
    return find_call_sites(symbols or _symbols(), files, changed={})


def test_every_import_form_resolves_to_the_symbol():
    files = {
        "a.py": "from billing.charge import charge\ncharge(1, 'usd')\n",
        "b.py": "from billing.charge import charge as pay\npay(1, 'usd')\n",
        "c.py": "import billing.charge as bc\nbc.charge(1, 'usd')\n",
        "d.py": "from billing import charge as mod\nmod.charge(1, 'usd')\n",
        "billing/e.py": "from .charge import charge\ncharge(1, 'usd')\n",
        "billing/charge.py": CHARGE_HEAD + "\n\ndef again():\n    return charge(1, 'usd', idempotency_key='k')\n",
        "src/pkg/f.py": "import billing.charge\nbilling.charge.charge(1, 'usd')\n",
    }
    scan = _sites(files)
    assert sorted((s.path, s.resolved) for s in scan.sites) == sorted(
        (p, True) for p in files)


def test_a_same_named_function_from_another_module_is_not_a_caller():
    files = {"x.py": "from payments.stripe import charge\ncharge(1, 'usd')\n",
             "y.py": "def charge(a, b):\n    return a\ncharge(1, 2)\n"}
    assert _sites(files).sites == []


def test_a_method_is_resolved_on_self_and_only_possible_elsewhere():
    base = "class Client:\n    def send(self, body):\n        return body\n\n    def go(self):\n        return self.send(1)\n"
    head = base.replace("def send(self, body):", "def send(self, body, *, retries):")
    syms = _symbols(base, head, "net/client.py")
    scan = find_call_sites(syms, {"net/client.py": head, "app.py": "def f(c):\n    return c.send(2)\n"}, changed={})
    by_path = {s.path: s for s in scan.sites}
    assert by_path["net/client.py"].resolved
    assert not by_path["app.py"].resolved and by_path["app.py"].mismatch is None


def test_a_file_that_does_not_parse_is_skipped_not_fatal():
    scan = _sites({"bad.py": "def (:\n", "a.py": "from billing.charge import charge\ncharge(1, 'usd')\n"})
    assert [s.path for s in scan.sites] == ["a.py"]


# --------------------------------------------------------------------------
# Does the caller still fit
# --------------------------------------------------------------------------

def _mismatches(caller_src):
    return [(s.path, s.line, s.mismatch) for s in _sites({"api/checkout.py": caller_src}).sites if s.mismatch]


def test_a_caller_missing_the_new_required_keyword_is_flagged():
    src = "from billing.charge import charge\n\n\ndef pay(total):\n    return charge(total, 'usd')\n"
    assert _mismatches(src) == [("api/checkout.py", 5, "missing required keyword argument 'idempotency_key'")]


def test_a_caller_already_passing_it_is_not_flagged():
    assert _mismatches("from billing.charge import charge\ncharge(1, 'usd', idempotency_key='k')\n") == []


def test_a_caller_forwarding_kwargs_cannot_be_checked_and_is_not_flagged():
    src = "from billing.charge import charge\n\ndef pay(*a, **kw):\n    return charge(*a, **kw)\n"
    [site] = _sites({"api/x.py": src}).sites
    assert site.mismatch is None and site.unchecked


def test_too_many_positionals_and_an_unknown_keyword_after_a_change():
    base = "def f(a, b, c=0):\n    return a\n"
    head = "def f(a, *, b_renamed=None):\n    return a\n"
    syms = _symbols(base, head, "m.py")
    files = {"u.py": "from m import f\nf(1, 2, 3)\nf(1, b=2)\n"}
    got = sorted((s.line, s.mismatch) for s in find_call_sites(syms, files, changed={}).sites)
    assert got == [(2, "takes at most 1 positional argument(s), got 3"), (3, "unexpected keyword argument 'b'")]


def test_a_call_already_broken_before_the_change_is_not_blamed_on_it():
    src = "from billing.charge import charge\ncharge(1)\n"  # missing currency, before and after
    assert _mismatches(src) == []


def test_every_caller_of_a_removed_function_is_flagged():
    head = CHARGE_BASE.split("\n\n\ndef refund")[0] + "\n"
    syms = _symbols(head=head)
    scan = find_call_sites(syms, {"r.py": "from billing.charge import refund\nrefund(3)\n"}, changed={})
    assert [(s.line, s.mismatch) for s in scan.sites] == [(2, "calls 'refund', which this change removes")]


def test_a_method_call_through_self_skips_self_in_the_check():
    base = "class C:\n    def send(self, body):\n        return body\n\n    def go(self):\n        return self.send(1)\n"
    head = base.replace("def send(self, body):", "def send(self, body, *, retries):").replace("self.send(1)", "self.send(1)")
    syms = [s for s in _symbols(base, head, "c.py") if s.qualname == "C.send"]
    [site] = find_call_sites(syms, {"c.py": head}, changed={}).sites
    assert site.mismatch == "missing required keyword argument 'retries'"


def test_a_constructor_call_is_checked_against_init():
    base = "class Client:\n    def __init__(self, url):\n        self.url = url\n"
    head = base.replace("(self, url)", "(self, url, token)")
    syms = _symbols(base, head, "net/client.py")
    scan = find_call_sites(syms, {"app.py": "from net.client import Client\nClient('u')\n"}, changed={})
    assert [s.mismatch for s in scan.sites] == ["missing required argument 'token'"]


def test_a_call_on_a_line_this_pr_changed_is_marked_in_diff():
    src = "from billing.charge import charge\ncharge(1, 'usd')\n"
    [site] = find_call_sites(_symbols(), {"a.py": src}, changed={"a.py": {2}}).sites
    assert site.in_diff


# --------------------------------------------------------------------------
# Dynamic use is counted, never flagged
# --------------------------------------------------------------------------

def test_dynamic_references_are_counted_and_not_flagged():
    src = _src('''
        import billing.charge as bc
        from billing.charge import charge

        handler = getattr(bc, "charge")
        HANDLERS = {"pay": charge}
        run(callback=charge)
    ''')
    scan = _sites({"d.py": src})
    assert scan.sites == []
    assert scan.dynamic_refs == {"charge": 3}


# --------------------------------------------------------------------------
# Which call sites go to the review
# --------------------------------------------------------------------------

def test_selection_puts_breaks_first_then_app_code_then_tests_one_file_at_a_time():
    callers = {f"app/m{i}.py": "from billing.charge import charge\ncharge(1, 'usd', idempotency_key='k')\n"
               for i in range(4)}
    callers["tests/test_pay.py"] = "from billing.charge import charge\ncharge(1, 'usd', idempotency_key='k')\n"
    callers["app/broken.py"] = "from billing.charge import charge\ncharge(1, 'usd')\n"
    callers["app/m0.py"] += "charge(2, 'usd', idempotency_key='k')\n"  # a second call in m0
    scan = _sites(callers)

    selected, omitted = select_call_sites(scan.sites, per_symbol=5, per_pr=15)
    assert [s.path for s in selected] == ["app/broken.py", "app/m0.py", "app/m1.py", "app/m2.py", "app/m3.py"]
    assert omitted == 2  # tests/test_pay.py and m0's second call


def test_the_per_pr_cap_holds_across_symbols():
    base = "".join(f"def f{i}(a):\n    return a\n\n\n" for i in range(5))
    head = base.replace("(a):", "(a, b):")
    syms = _symbols(base, head, "m.py")
    files = {f"u{j}.py": "from m import " + ", ".join(f"f{i}" for i in range(5)) + "\n"
             + "".join(f"f{i}(1, 2)\n" for i in range(5)) for j in range(5)}
    selected, omitted = select_call_sites(find_call_sites(syms, files, changed={}).sites, per_symbol=5, per_pr=15)
    assert len(selected) == 15 and omitted == 10


def test_breaks_are_always_reported_even_past_the_cap():
    callers = {f"app/b{i}.py": "from billing.charge import charge\ncharge(1, 'usd')\n" for i in range(8)}
    selected, _ = select_call_sites(_sites(callers).sites, per_symbol=5, per_pr=15)
    assert sum(1 for s in selected if s.mismatch) == 8


# --------------------------------------------------------------------------
# End to end
# --------------------------------------------------------------------------

def test_analyze_end_to_end():
    caller = "from billing.charge import charge\n\n\ndef checkout(total):\n    return charge(total, 'usd')\n"
    report = analyze(
        head_files={"billing/charge.py": CHARGE_HEAD, "api/checkout.py": caller},
        base_files={"billing/charge.py": CHARGE_BASE},
        patches={"billing/charge.py": _patch(CHARGE_BASE, CHARGE_HEAD, "billing/charge.py")},
        per_symbol=5, per_pr=15,
    )
    assert [s.qualname for s in report.symbols] == ["charge"]
    assert [(s.path, s.line, s.mismatch) for s in report.sites] == [
        ("api/checkout.py", 5, "missing required keyword argument 'idempotency_key'")]
    assert report.omitted == 0 and report.dynamic_refs == {}


def test_analyze_ignores_non_python_and_unparseable_changes():
    report = analyze(head_files={"README.md": "x", "bad.py": "def (:"}, base_files={"bad.py": "def (:"},
                     patches={"README.md": "@@ -1 +1 @@\n-y\n+x\n", "bad.py": "@@ -1 +1 @@\n-def (:\n+def (:\n"},
                     per_symbol=5, per_pr=15)
    assert report.symbols == [] and report.sites == []
