"""Drift guard: every ``Finding.details`` key the backend reads or writes must be
declared on a model in ``app.schemas.finding_details``.

The guard AST-walks ``app/`` and collects keys from:

1. ``<details expr>.get("key")`` / ``.setdefault`` / ``.pop`` calls,
2. ``<details expr>["key"]`` subscripts (reads and writes),
3. ``"key" in <details expr>`` membership tests,
4. Mongo dotted-path string literals (``"details.key"`` / ``"$details.key"``).

A "details expression" is a name or attribute (path) ending in ``details``
(``details``, ``finding.details``, ``merged_details``, …) or a chained
``x.get("details")`` / ``x["details"]``.

Scope rule: a key passes when it is declared on at least ONE details model
(union check, not per-finding-type), so adding a legitimate analyzer field means
touching only the schema. Dotted paths are additionally checked one level deep
through the known entry-list/object fields in ``_NESTED_MODELS``.
"""

import ast
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from app.schemas import finding as finding_typed_dicts
from app.schemas import finding_details

APP_ROOT = Path(finding_details.__file__).resolve().parents[1]

# Keys matched by the AST walk that are not Finding.details payloads, or that are
# intentionally undeclared. Every entry needs a reason; do not park real drift here.
ALLOWED_UNDECLARED: dict[str, str] = {
    # pymongo BulkWriteError.details in repositories/base.py, not a finding payload.
    "writeErrors": "pymongo BulkWriteError.details key",
    "nInserted": "pymongo BulkWriteError.details key",
    # Synthetic in-memory dicts inside the recommendation engine, never persisted:
    # recommendations._collect_typosquat_findings remaps imitated_package -> similar_to
    # for incidents.process_typosquatting; risks.py accumulates per-package scratch data.
    "similar_to": "in-memory remap for incidents.process_typosquatting",
    "version": "recommendation/risks.py per-package scratch dict",
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
    location: str


def _dotted_path_use(value: str, location: str) -> KeyUse | None:
    prefix = value.removeprefix("$")
    if not prefix.startswith("details."):
        return None
    # Skip Mongo operators and positional segments ($, $[...], numeric indices).
    segments = [
        seg
        for seg in prefix.split(".")[1:]
        if seg and not seg.startswith("$") and not seg.isdigit() and not seg.startswith("[")
    ]
    if not segments:
        return None
    return KeyUse(key=".".join(segments), location=location)


def _collect_file_uses(path: Path) -> list[KeyUse]:
    tree = ast.parse(path.read_text(), filename=str(path))
    rel = path.relative_to(APP_ROOT.parent)
    uses: list[KeyUse] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in ("get", "setdefault", "pop")
                and _is_details_expr(func.value)
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                uses.append(KeyUse(node.args[0].value, f"{rel}:{node.lineno}"))
        elif isinstance(node, ast.Subscript):
            if (
                isinstance(node.slice, ast.Constant)
                and isinstance(node.slice.value, str)
                and _is_details_expr(node.value)
            ):
                uses.append(KeyUse(node.slice.value, f"{rel}:{node.lineno}"))
        elif isinstance(node, ast.Compare):
            if (
                len(node.ops) == 1
                and isinstance(node.ops[0], (ast.In, ast.NotIn))
                and isinstance(node.left, ast.Constant)
                and isinstance(node.left.value, str)
                and _is_details_expr(node.comparators[0])
            ):
                uses.append(KeyUse(node.left.value, f"{rel}:{node.lineno}"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            use = _dotted_path_use(node.value, f"{rel}:{node.lineno}")
            if use:
                uses.append(use)

    return uses


def _collect_all_uses() -> list[KeyUse]:
    uses: list[KeyUse] = []
    for path in sorted(APP_ROOT.rglob("*.py")):
        uses.extend(_collect_file_uses(path))
    assert uses, "guard collected zero details-key uses; the extractor is broken"
    return uses


def _violations(uses: list[KeyUse], declared: set[str]) -> dict[str, list[str]]:
    bad: dict[str, list[str]] = {}
    for use in uses:
        segments = use.key.split(".")
        head = segments[0]
        if head in ALLOWED_UNDECLARED:
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
    used_keys = {use.key.split(".")[0] for use in _collect_all_uses()}
    stale = set(ALLOWED_UNDECLARED) - used_keys
    assert not stale, f"ALLOWED_UNDECLARED entries no longer referenced anywhere, remove them: {sorted(stale)}"


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
    same-named classes elsewhere are not matched.
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
