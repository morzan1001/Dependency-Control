"""Drift guard: every ``Finding.details`` key the backend reads or writes must be
declared on a model in ``app.schemas.finding_details``.

The guard AST-walks ``app/`` and collects keys from:

1. ``<details expr>.get(K)`` / ``.setdefault`` / ``.pop`` calls,
2. ``<details expr>[K]`` subscripts (reads and writes),
3. ``K in <details expr>`` membership tests,
4. Mongo dotted-path string literals (``"details.key"`` / ``"$details.key"``),
   including f-strings whose placeholders resolve to string constants.

``K`` may be a string literal or a name that resolves to a module-level string
constant, in the same file or imported from another ``app.*`` module (this is
what keeps ``DETAILS_KEY_*`` reads honest against the writers' literals).

A "details expression" is a name or attribute (path) ending in ``details``
(``details``, ``finding.details``, ``merged_details``, …) or a chained
``x.get("details")`` / ``x["details"]``.

Scope rule: a key passes when it is declared on at least ONE details model
(union check, not per-finding-type), so adding a legitimate analyzer field means
touching only the schema. Dotted paths are additionally checked one level deep
through the known entry-list/object fields in ``_NESTED_MODELS``.

KNOWN BLIND SPOTS — do not over-trust a green guard:

- Aliased variables: ``d = finding["details"]; d.get("x")`` or helpers taking a
  details dict under another parameter name (live example:
  ``findings_delta._first_id(details, *keys)`` — the call sites pass literal key
  strings that are NOT collected). Keep details-holding variables named
  ``details``/``*_details`` so the walker sees them.
- Keys built at runtime (concatenation, ``%``/``.format``, comprehension over a
  key list) and f-string placeholders that are not resolvable constants — the
  unresolvable tail of a dotted path is not checked.
- Wrong-LEVEL reads of a declared key: the union rule cannot flag reading e.g.
  ``category`` at the merged-SAST top level just because the key legitimately
  exists on the per-scanner shape.
- Writer ``**spread`` kwargs (e.g. ``CryptoCertificateDetails(bom_ref=..., **details)``)
  bypass the writer-side kwarg check; with ``extra="allow"`` an undeclared key in
  the spread dict lands silently unless some reader consumes it.
"""

import ast
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from app.schemas import finding as finding_typed_dicts
from app.schemas import finding_details

APP_ROOT = Path(finding_details.__file__).resolve().parents[1]

# (key, file) pairs matched by the AST walk that are not Finding.details payloads.
# Location-scoped on purpose: the same key appearing in any other file still fails.
# Every entry needs a reason; do not park real drift here.
ALLOWED_UNDECLARED: dict[tuple[str, str], str] = {
    ("writeErrors", "app/repositories/base.py"): "pymongo BulkWriteError.details key",
    ("nInserted", "app/repositories/base.py"): "pymongo BulkWriteError.details key",
}

# Dotted Mongo paths are validated one level deep through these fields.
_NESTED_MODELS: dict[str, str] = {
    "vulnerabilities": "VulnerabilityEntryDetails",
    "quality_issues": "QualityIssueEntry",
    "sast_findings": "SastFindingEntry",
    "matched_rules": "MatchedRuleEntry",
    "reachability": "ReachabilityInfo",
    "outdated_info": "OutdatedInfo",
    "quality_info": "QualityInfo",
    "license_info": "LicenseInfo",
    "eol_info": "EolInfo",
    "scorecard_context": "ScorecardContext",
    "start": "LineSpan",
    "end": "LineSpan",
}


def _details_models() -> list[type[BaseModel]]:
    models = [
        obj
        for obj in vars(finding_details).values()
        if isinstance(obj, type) and issubclass(obj, BaseModel) and obj.__module__ == finding_details.__name__
    ]
    assert models, "no details models found in app.schemas.finding_details"
    return models


def _declared_keys() -> set[str]:
    return {name for model in _details_models() for name in model.model_fields}


def _model_fields(model_name: str) -> set[str]:
    return set(getattr(finding_details, model_name).model_fields)


def _is_details_expr(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "details" or node.id.endswith("_details")
    if isinstance(node, ast.Attribute):
        return node.attr == "details" or node.attr.endswith("_details")
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in ("get", "setdefault") and node.args:
            first = node.args[0]
            return isinstance(first, ast.Constant) and first.value == "details"
    if isinstance(node, ast.Subscript):
        return isinstance(node.slice, ast.Constant) and node.slice.value == "details"
    if isinstance(node, ast.BoolOp):
        return any(_is_details_expr(value) for value in node.values)
    return False


@dataclass(frozen=True)
class KeyUse:
    key: str  # dotted path, first segment is the details key
    file: str  # path relative to backend/, e.g. "app/services/analysis/stats.py"
    location: str  # "file:line"


_MODULE_CONSTANTS_CACHE: dict[Path, dict[str, str]] = {}


def _module_string_constants(path: Path) -> dict[str, str]:
    """Module-level ``NAME = "literal"`` assignments of a source file."""
    cached = _MODULE_CONSTANTS_CACHE.get(path)
    if cached is not None:
        return cached
    constants: dict[str, str] = {}
    if path.is_file():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in tree.body:
            target = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                target = node.targets[0].id
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                target = node.target.id
            if target and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                constants[target] = node.value.value
    _MODULE_CONSTANTS_CACHE[path] = constants
    return constants


def _module_path(module: str) -> Path | None:
    if not module.startswith("app."):
        return None
    candidate = APP_ROOT.parent / (module.replace(".", "/") + ".py")
    if candidate.is_file():
        return candidate
    package_init = APP_ROOT.parent / module.replace(".", "/") / "__init__.py"
    return package_init if package_init.is_file() else None


def _constant_env(tree: ast.Module, path: Path) -> dict[str, str]:
    """Names in this file that resolve to string constants (local or imported from app.*)."""
    env = dict(_module_string_constants(path))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ImportFrom) and node.module and node.level == 0):
            continue
        source = _module_path(node.module)
        if source is None:
            continue
        source_constants = _module_string_constants(source)
        for alias in node.names:
            if alias.name in source_constants:
                env[alias.asname or alias.name] = source_constants[alias.name]
    return env


def _resolve_key(node: ast.expr, env: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    return None


def _resolve_fstring(node: ast.JoinedStr, env: dict[str, str]) -> tuple[str, bool]:
    """Concatenate resolvable parts; returns (value, fully_resolved)."""
    parts: list[str] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            parts.append(value.value)
            continue
        if isinstance(value, ast.FormattedValue):
            resolved = _resolve_key(value.value, env)
            if resolved is not None:
                parts.append(resolved)
                continue
        return "".join(parts), False
    return "".join(parts), True


def _path_segments(value: str) -> list[str] | None:
    prefix = value.removeprefix("$")
    if not prefix.startswith("details."):
        return None
    # Skip Mongo operators and positional segments ($, $[...], numeric indices).
    return [
        seg
        for seg in prefix.split(".")[1:]
        if seg and not seg.startswith("$") and not seg.isdigit() and not seg.startswith("[")
    ]


def _dotted_path_use(value: str, file: str, location: str, complete: bool = True) -> KeyUse | None:
    segments = _path_segments(value)
    if segments is None:
        return None
    if not complete:
        # The trailing segment may be a partial prefix of an unresolvable placeholder.
        segments = segments[:-1] if not value.endswith(".") else segments
    if not segments:
        return None
    return KeyUse(key=".".join(segments), file=file, location=location)


def _collect_file_uses(path: Path) -> list[KeyUse]:
    tree = ast.parse(path.read_text(), filename=str(path))
    rel = str(path.relative_to(APP_ROOT.parent))
    env = _constant_env(tree, path)
    uses: list[KeyUse] = []

    def add(key: str | None, lineno: int) -> None:
        if key is not None:
            uses.append(KeyUse(key=key, file=rel, location=f"{rel}:{lineno}"))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in ("get", "setdefault", "pop")
                and _is_details_expr(func.value)
                and node.args
            ):
                add(_resolve_key(node.args[0], env), node.lineno)
        elif isinstance(node, ast.Subscript):
            if _is_details_expr(node.value):
                add(_resolve_key(node.slice, env), node.lineno)
        elif isinstance(node, ast.Compare):
            if (
                len(node.ops) == 1
                and isinstance(node.ops[0], (ast.In, ast.NotIn))
                and _is_details_expr(node.comparators[0])
            ):
                add(_resolve_key(node.left, env), node.lineno)
        elif isinstance(node, ast.JoinedStr):
            value, complete = _resolve_fstring(node, env)
            use = _dotted_path_use(value, rel, f"{rel}:{node.lineno}", complete=complete)
            if use:
                uses.append(use)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            use = _dotted_path_use(node.value, rel, f"{rel}:{node.lineno}")
            if use:
                uses.append(use)

    return uses


_USES_CACHE: list[KeyUse] = []


def _collect_all_uses() -> list[KeyUse]:
    if not _USES_CACHE:
        for path in sorted(APP_ROOT.rglob("*.py")):
            _USES_CACHE.extend(_collect_file_uses(path))
    assert _USES_CACHE, "guard collected zero details-key uses; the extractor is broken"
    return _USES_CACHE


def _violations(uses: list[KeyUse], declared: set[str]) -> dict[str, list[str]]:
    bad: dict[str, list[str]] = {}
    for use in uses:
        segments = use.key.split(".")
        head = segments[0]
        if (head, use.file) in ALLOWED_UNDECLARED:
            continue
        if head not in declared:
            bad.setdefault(head, []).append(use.location)
            continue
        if len(segments) > 1 and head in _NESTED_MODELS and segments[1] not in _model_fields(_NESTED_MODELS[head]):
            bad.setdefault(f"{head}.{segments[1]}", []).append(use.location)
    return bad


def test_every_consumed_details_key_is_declared():
    declared = _declared_keys()
    bad = _violations(_collect_all_uses(), declared)

    if bad:
        lines = ["Undeclared Finding.details keys (declare them in app/schemas/finding_details.py"]
        lines.append("next to their writer, or add a reasoned ALLOWED_UNDECLARED entry):\n")
        for key in sorted(bad):
            lines.append(f"  {key}")
            for loc in sorted(set(bad[key])):
                lines.append(f"    - {loc}")
        raise AssertionError("\n".join(lines))


def test_allowlist_entries_are_still_referenced():
    used_pairs = {(use.key.split(".")[0], use.file) for use in _collect_all_uses()}
    stale = set(ALLOWED_UNDECLARED) - used_pairs
    assert not stale, f"ALLOWED_UNDECLARED entries no longer referenced at their file, remove them: {sorted(stale)}"


def test_details_key_constants_point_at_declared_fields():
    """Backstop for constant-mediated reads: renaming a DETAILS_KEY_* value must fail here
    even if every read site goes through the constant."""
    from app.core import constants

    declared = _declared_keys()
    bad = {
        name: getattr(constants, name)
        for name in dir(constants)
        if name.startswith("DETAILS_KEY_") and getattr(constants, name) not in declared
    }
    assert not bad, f"DETAILS_KEY_* constants whose value is not a declared details field: {bad}"


def test_aggregator_typed_dicts_match_details_models():
    """The dict-merging TypedDicts in app.schemas.finding must not drift from the models."""
    pairs = {
        "VulnerabilityEntry": "VulnerabilityEntryDetails",
        "VulnerabilityAggregatedDetails": "VulnerabilityDetails",
        "QualityEntry": "QualityIssueEntry",
        "QualityAggregatedDetails": "QualityDetails",
    }
    for typed_dict_name, model_name in pairs.items():
        typed_dict = getattr(finding_typed_dicts, typed_dict_name)
        missing = set(typed_dict.__annotations__) - _model_fields(model_name)
        assert not missing, f"{typed_dict_name} declares keys missing on {model_name}: {sorted(missing)}"


def test_writer_construction_kwargs_are_declared_fields():
    """``extra="allow"`` accepts typo'd kwargs silently, so check construction sites by AST.

    Only names imported from ``app.schemas.finding_details`` count, so unrelated
    same-named classes elsewhere are not matched. ``**spread`` arguments cannot be
    checked statically (see module docstring).
    """
    model_names = {model.__name__ for model in _details_models()}
    bad: list[str] = []
    for path in sorted(APP_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        rel = path.relative_to(APP_ROOT.parent)
        imported: dict[str, str] = {}  # local alias -> model name
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == finding_details.__name__:
                for alias in node.names:
                    if alias.name in model_names:
                        imported[alias.asname or alias.name] = alias.name
        if not imported:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            model_name = imported.get(node.func.id)
            if model_name is None:
                continue
            fields = _model_fields(model_name)
            for kw in node.keywords:
                if kw.arg is not None and kw.arg not in fields:
                    bad.append(f"{rel}:{node.lineno} — {model_name}({kw.arg}=...) is not a declared field")
    assert not bad, "writers pass kwargs that are not schema fields:\n" + "\n".join(bad)
