"""Impact analysis for PR reviews: who calls what this PR changed.

For each Python function, method or class a PR changes, find its call
sites elsewhere in the repository and flag the callers that no longer fit
the new signature. Pure: no network, no model. The worker supplies the
repository's files (codeguard/github/tarball.py) and the review graph's
review_impact node turns the result into findings and the summary's
"Callers outside this diff" section.

WHAT IS CHANGED. A def whose AST differs between base and head. Compared by
AST, not by patch line numbers, so an edit that only deletes lines counts
and a def that merely moved does not. A def present in base and gone from
head is "removed". A new def has no existing callers and is skipped.
__init__ is folded into its class: changing it changes how the class is
called.

HOW CALLS ARE RESOLVED. Through the caller's imports, every form:
`from m import f [as g]`, `import m [as x]` then `x.f()`, `from pkg import
m` then `m.f()`, relative imports, and bare calls in the defining module.
A method is resolved through `self.`/`cls.` inside its own class; a call
like `obj.method()` anywhere else cannot be tied to the class without type
information, so it is a POSSIBLE call site -- context for the reviewer,
never flagged.

WHAT IS FLAGGED. Only a resolved call whose arguments no longer bind to the
new signature AND did bind to the old one. A call that was already broken
is not this PR's doing. A call through `*args` / `**kwargs` cannot be
checked and is marked unchecked, not flagged.

DYNAMIC USE is counted, never flagged: getattr(x, "name"), the function
passed as a value (callbacks, registries). The summary says how many were
not analysed rather than implying there were none.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_TEST_PATH = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_test\.py$")

SNIPPET_CONTEXT = 8
MAX_BREAKS_REPORTED = 20
_MAX_SOURCE_LINES = 60


# --------------------------------------------------------------------------
# Patches and module names
# --------------------------------------------------------------------------

def added_lines(patch: str) -> set[int]:
    """Head-side line numbers of the lines a unified-diff patch adds."""
    out: set[int] = set()
    line: int | None = None
    for raw in patch.splitlines():
        match = _HUNK.match(raw)
        if match:
            line = int(match.group(1))
            continue
        if line is None or raw.startswith("\\"):
            continue
        if raw.startswith("+"):
            out.add(line)
            line += 1
        elif not raw.startswith("-"):
            line += 1
    return out


def module_name(path: str) -> str:
    """billing/charge.py -> billing.charge; pkg/__init__.py -> pkg; a
    leading src/ is dropped, since that is not part of the import path."""
    parts = path.replace("\\", "/").removesuffix(".py").split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if len(parts) > 1 and parts[0] == "src":
        parts = parts[1:]
    return ".".join(parts)


def _package(path: str) -> list[str]:
    parts = module_name(path).split(".")
    return parts if path.replace("\\", "/").endswith("__init__.py") else parts[:-1]


def _is_test(path: str) -> bool:
    return bool(_TEST_PATH.search(path.replace("\\", "/")))


# --------------------------------------------------------------------------
# Signatures
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Params:
    posonly: tuple[str, ...]
    positional: tuple[str, ...]
    n_required_positional: int
    vararg: bool
    kwonly: tuple[str, ...]
    kwonly_required: frozenset[str]
    kwarg: bool


def _params(args: ast.arguments, *, drop_first: bool) -> Params:
    positional = [a.arg for a in args.posonlyargs + args.args]
    n_posonly = len(args.posonlyargs)
    required = len(positional) - len(args.defaults)
    if drop_first and positional:
        positional = positional[1:]
        required = max(0, required - 1)
        n_posonly = max(0, n_posonly - 1)
    return Params(
        posonly=tuple(positional[:n_posonly]),
        positional=tuple(positional),
        n_required_positional=required,
        vararg=args.vararg is not None,
        kwonly=tuple(a.arg for a in args.kwonlyargs),
        kwonly_required=frozenset(a.arg for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is None),
        kwarg=args.kwarg is not None,
    )


def binding_error(params: Params, n_positional: int, keywords: list[str]) -> str | None:
    """Why a call with this many positionals and these keywords would not
    bind, or None if it would."""
    if not params.vararg and n_positional > len(params.positional):
        return f"takes at most {len(params.positional)} positional argument(s), got {n_positional}"
    for name in keywords:
        if name in params.posonly:
            return f"positional-only argument '{name}' passed by keyword"
        if name not in params.positional and name not in params.kwonly and not params.kwarg:
            return f"unexpected keyword argument '{name}'"
    filled = set(params.positional[:n_positional]) | set(keywords)
    for name in params.positional[:params.n_required_positional]:
        if name not in filled:
            return f"missing required argument '{name}'"
    for name in params.kwonly:
        if name in params.kwonly_required and name not in keywords:
            return f"missing required keyword argument '{name}'"
    return None


def _is_static(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in node.decorator_list)


# --------------------------------------------------------------------------
# What changed
# --------------------------------------------------------------------------

@dataclass
class ChangedSymbol:
    path: str
    module: str
    qualname: str          # "charge", "Client", "Client.send"
    kind: str              # function | method | class | removed
    line: int              # the head def line (the base one when removed)
    base: Params | None
    head: Params | None
    signature_changed: bool
    body_changed: bool
    class_name: str | None = None
    base_source: str = ""
    head_source: str = ""

    @property
    def name(self) -> str:
        return self.qualname.rsplit(".", 1)[-1]

    @property
    def full(self) -> str:
        return f"{self.module}.{self.qualname}"

    @property
    def is_method(self) -> bool:
        return self.class_name is not None


_FuncDef = (ast.FunctionDef, ast.AsyncFunctionDef)


def _defs(tree: ast.Module) -> dict[str, tuple[ast.AST, str, str | None]]:
    """qualname -> (node, kind, class name). Top-level functions and
    classes, and the methods of top-level classes, except __init__."""
    out: dict[str, tuple[ast.AST, str, str | None]] = {}
    for node in tree.body:
        if isinstance(node, _FuncDef):
            out[node.name] = (node, "function", None)
        elif isinstance(node, ast.ClassDef):
            out[node.name] = (node, "class", None)
            for sub in node.body:
                if isinstance(sub, _FuncDef) and sub.name != "__init__":
                    out[f"{node.name}.{sub.name}"] = (sub, "method", node.name)
    return out


def _init(cls: ast.ClassDef):
    return next((n for n in cls.body if isinstance(n, _FuncDef) and n.name == "__init__"), None)


def _signature(node: ast.AST, kind: str) -> Params | None:
    if kind == "function":
        return _params(node.args, drop_first=False)
    if kind == "method":
        return _params(node.args, drop_first=not _is_static(node))
    init = _init(node)
    # A class with no __init__ of its own is called with whatever it
    # inherits, which this does not know. Unknown is not "no arguments".
    return _params(init.args, drop_first=True) if init else None


def _shape(node: ast.AST, kind: str) -> tuple[str, str]:
    """(signature dump, body dump), positions excluded."""
    if kind == "class":
        init = _init(node)
        return (ast.dump(init.args) if init else "", ast.dump(init) if init else "")
    return ast.dump(node.args), ast.dump(ast.Module(body=node.body, type_ignores=[]))


def _source(src: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(src, node) or ""
    lines = segment.splitlines()
    if len(lines) > _MAX_SOURCE_LINES:
        lines = lines[:_MAX_SOURCE_LINES] + ["    ..."]
    return "\n".join(lines)


def changed_symbols(path: str, base_src: str, head_src: str) -> list[ChangedSymbol]:
    """The defs this change touched in one file. Raises SyntaxError if
    either side does not parse."""
    base_defs = _defs(ast.parse(base_src))
    head_defs = _defs(ast.parse(head_src or ""))
    module = module_name(path)
    out: list[ChangedSymbol] = []

    for qualname, (head_node, kind, cls) in head_defs.items():
        if qualname not in base_defs or base_defs[qualname][1] != kind:
            continue  # new: nobody calls it yet
        base_node = base_defs[qualname][0]
        base_sig, base_body = _shape(base_node, kind)
        head_sig, head_body = _shape(head_node, kind)
        if (base_sig, base_body) == (head_sig, head_body):
            continue
        out.append(ChangedSymbol(
            path=path, module=module, qualname=qualname, kind=kind, line=head_node.lineno,
            base=_signature(base_node, kind), head=_signature(head_node, kind),
            signature_changed=base_sig != head_sig, body_changed=base_body != head_body,
            class_name=cls, base_source=_source(base_src, base_node), head_source=_source(head_src, head_node),
        ))

    removed_classes = {q for q, (_, k, _c) in base_defs.items() if k == "class" and q not in head_defs}
    for qualname, (base_node, kind, cls) in base_defs.items():
        if qualname in head_defs or (cls and cls in removed_classes):
            continue
        out.append(ChangedSymbol(
            path=path, module=module, qualname=qualname, kind="removed", line=base_node.lineno,
            base=_signature(base_node, kind), head=None, signature_changed=True, body_changed=True,
            class_name=cls, base_source=_source(base_src, base_node),
        ))
    return sorted(out, key=lambda s: s.line)


# --------------------------------------------------------------------------
# Where it is called from
# --------------------------------------------------------------------------

@dataclass
class CallSite:
    path: str
    line: int
    end_line: int
    qualname: str
    resolved: bool
    mismatch: str | None = None
    unchecked: bool = False
    in_diff: bool = False
    is_test: bool = False
    snippet: str = ""


@dataclass
class Scan:
    sites: list[CallSite] = field(default_factory=list)
    dynamic_refs: dict[str, int] = field(default_factory=dict)


def _aliases(tree: ast.Module, path: str) -> dict[str, str]:
    package = _package(path)
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    out[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    out[top] = top
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                keep = len(package) - (node.level - 1)
                if keep < 0:
                    continue
                base = ".".join(package[:keep] + ([node.module] if node.module else []))
            else:
                base = node.module or ""
            for alias in node.names:
                if alias.name != "*":
                    out[alias.asname or alias.name] = f"{base}.{alias.name}" if base else alias.name
    return out


class _Resolver:
    def __init__(self, tree: ast.Module, path: str):
        self.module = module_name(path)
        self.aliases = _aliases(tree, path)
        self.local = {n.name for n in tree.body if isinstance(n, (*_FuncDef, ast.ClassDef))}

    def dotted(self, expr: ast.AST) -> str | None:
        if isinstance(expr, ast.Name):
            if expr.id in self.local:
                return f"{self.module}.{expr.id}"
            return self.aliases.get(expr.id)
        if isinstance(expr, ast.Attribute):
            base = self.dotted(expr.value)
            return f"{base}.{expr.attr}" if base else None
        return None


def _enclosing_classes(tree: ast.Module) -> dict[int, str]:
    out: dict[int, str] = {}
    for cls in tree.body:
        if isinstance(cls, ast.ClassDef):
            for node in ast.walk(cls):
                if isinstance(node, ast.Call):
                    out[id(node)] = cls.name
    return out


def _check(sym: ChangedSymbol, call: ast.Call) -> tuple[str | None, bool]:
    """(mismatch, unchecked) for a resolved call."""
    if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        return None, True
    if sym.kind == "removed":
        return f"calls '{sym.name}', which this change removes", False
    if sym.head is None:
        return None, True
    n_positional = len(call.args)
    keywords = [k.arg for k in call.keywords]
    now = binding_error(sym.head, n_positional, keywords)
    before = binding_error(sym.base, n_positional, keywords) if sym.base else None
    return (now if now and not before else None), False


def find_call_sites(
    symbols: list[ChangedSymbol], files: dict[str, str], changed: dict[str, set[int]],
) -> Scan:
    """Every call to a changed symbol in `files` (path -> source), with
    mismatches checked, plus a count of dynamic references per symbol."""
    scan = Scan()
    if not symbols:
        return scan
    targets = {s.full: s for s in symbols if not s.is_method}
    methods: dict[str, list[ChangedSymbol]] = {}
    for s in symbols:
        if s.is_method:
            methods.setdefault(s.name, []).append(s)
    names = {s.name for s in symbols}

    for path, src in sorted(files.items()):
        if not path.endswith(".py") or not any(n in src for n in names):
            continue
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError):
            continue
        resolver = _Resolver(tree, path)
        enclosing = _enclosing_classes(tree)
        lines = src.splitlines()
        call_funcs: set[int] = set()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call_funcs.add(id(node.func))
            sym, resolved = None, False
            dotted = resolver.dotted(node.func)
            if dotted in targets:
                sym, resolved = targets[dotted], True
            elif isinstance(node.func, ast.Attribute) and node.func.attr in methods:
                receiver = node.func.value
                for candidate in methods[node.func.attr]:
                    if (isinstance(receiver, ast.Name) and receiver.id in ("self", "cls")
                            and resolver.module == candidate.module
                            and enclosing.get(id(node)) == candidate.class_name):
                        sym, resolved = candidate, True
                        break
                else:
                    if dotted is None and not (isinstance(receiver, ast.Name) and receiver.id in ("self", "cls")):
                        sym = methods[node.func.attr][0]
            if sym is None:
                continue
            mismatch, unchecked = _check(sym, node) if resolved else (None, False)
            end = getattr(node, "end_lineno", node.lineno) or node.lineno
            lo, hi = max(0, node.lineno - 1 - SNIPPET_CONTEXT), min(len(lines), end + SNIPPET_CONTEXT)
            scan.sites.append(CallSite(
                path=path, line=node.lineno, end_line=end, qualname=sym.qualname, resolved=resolved,
                mismatch=mismatch, unchecked=unchecked, in_diff=node.lineno in changed.get(path, set()),
                is_test=_is_test(path), snippet="\n".join(lines[lo:hi]),
            ))

        for node in ast.walk(tree):
            qualname = None
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
                    and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
                    and node.args[1].value in names):
                qualname = next(s.qualname for s in symbols if s.name == node.args[1].value)
            elif (isinstance(node, (ast.Name, ast.Attribute)) and isinstance(getattr(node, "ctx", None), ast.Load)
                    and id(node) not in call_funcs):
                dotted = resolver.dotted(node)
                if dotted in targets:
                    qualname = targets[dotted].qualname
            if qualname:
                scan.dynamic_refs[qualname] = scan.dynamic_refs.get(qualname, 0) + 1
    return scan


# --------------------------------------------------------------------------
# Which call sites go to the review
# --------------------------------------------------------------------------

def select_call_sites(
    sites: list[CallSite], *, per_symbol: int, per_pr: int,
) -> tuple[list[CallSite], int]:
    """(chosen, how many were left out).

    Every caller that no longer fits is kept (up to MAX_BREAKS_REPORTED):
    those are the findings. The rest is context for the reviewer, chosen
    in this order -- resolved before possible, application code before
    tests, one per file before a second from the same file -- capped at
    `per_symbol` (breaks included) and `per_pr` overall, shared out across
    symbols in turn.
    """
    breaks = sorted((s for s in sites if s.mismatch), key=lambda s: (s.path, s.line))[:MAX_BREAKS_REPORTED]
    rest = sorted((s for s in sites if not s.mismatch), key=lambda s: (not s.resolved, s.is_test, s.path, s.line))

    per_sym: dict[str, list[CallSite]] = {}
    for site in rest:
        per_sym.setdefault(site.qualname, []).append(site)
    breaks_by_sym: dict[str, int] = {}
    for site in breaks:
        breaks_by_sym[site.qualname] = breaks_by_sym.get(site.qualname, 0) + 1

    picks: dict[str, list[CallSite]] = {}
    for qualname, candidates in per_sym.items():
        room = max(0, per_symbol - breaks_by_sym.get(qualname, 0))
        seen: set[str] = set()
        first = [s for s in candidates if not (s.path in seen or seen.add(s.path))]
        ordered = first + [s for s in candidates if s not in first]
        picks[qualname] = ordered[:room]

    chosen = list(breaks)
    queues = list(picks.values())
    while len(chosen) < per_pr and any(queues):
        for queue in queues:
            if queue and len(chosen) < per_pr:
                chosen.append(queue.pop(0))
    return chosen, len(sites) - len(chosen)


# --------------------------------------------------------------------------
# End to end
# --------------------------------------------------------------------------

@dataclass
class ImpactReport:
    symbols: list[ChangedSymbol]
    sites: list[CallSite]
    omitted: int
    dynamic_refs: dict[str, int]
    total_sites: int = 0


def analyze(
    *, head_files: dict[str, str], base_files: dict[str, str], patches: dict[str, str],
    per_symbol: int, per_pr: int,
) -> ImpactReport:
    """head_files: the repository's Python files at the PR head.
    base_files: the base versions of the PR's changed files."""
    symbols: list[ChangedSymbol] = []
    changed_lines: dict[str, set[int]] = {}
    for path, patch in sorted(patches.items()):
        if not path.endswith(".py"):
            continue
        changed_lines[path] = added_lines(patch or "")
        base_src = base_files.get(path)
        if base_src is None:
            continue  # a new file: nothing calls it yet
        try:
            symbols += changed_symbols(path, base_src, head_files.get(path, ""))
        except (SyntaxError, ValueError):
            continue
    scan = find_call_sites(symbols, head_files, changed_lines)
    selected, omitted = select_call_sites(scan.sites, per_symbol=per_symbol, per_pr=per_pr)
    return ImpactReport(symbols=symbols, sites=selected, omitted=omitted,
                        dynamic_refs=scan.dynamic_refs, total_sites=len(scan.sites))
