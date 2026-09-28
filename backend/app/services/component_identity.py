"""Package-name identity and name-join helpers shared by aggregation, analytics and reachability."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, TypeVar

_QUALIFIER_SEPARATORS = (":", "/")
JVM_LANGUAGES = frozenset({"java", "kotlin", "scala", "groovy"})
_CALLGRAPH_LANGUAGES = frozenset({"python", "go", "javascript", "typescript", *JVM_LANGUAGES})
_CALLGRAPH_LANGUAGE_ALIASES = {
    "golang": "go",
    "js": "javascript",
    "node": "javascript",
    "nodejs": "javascript",
    "ts": "typescript",
    "py": "python",
}

_T = TypeVar("_T")


def npm_package_key(name: str) -> str:
    """Reduce an npm specifier to its package: ``@scope/pkg`` keeps two segments."""
    parts = name.split("/")
    if name.startswith("@") and len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}".lower()
    return parts[0].lower()


def canonical_callgraph_language(raw: str) -> str:
    """Canonical spelling of an uploaded callgraph language; ValueError for one without callgraph support."""
    language = raw.strip().lower()
    language = _CALLGRAPH_LANGUAGE_ALIASES.get(language, language)
    if language not in _CALLGRAPH_LANGUAGES:
        supported = ", ".join(sorted(_CALLGRAPH_LANGUAGES))
        raise ValueError(f"unsupported callgraph language '{raw}'; supported: {supported}")
    return language


def canonical_module_key(name: str, language: str) -> str:
    """Canonical lookup key for a module/package name, per language.

    The single meeting point between the callgraph parsers, which key stored modules by
    it, and reachability enrichment, which derives it from a finding's component name.
    """
    if name.startswith(("./", "../")):
        return name

    language = language.lower()

    if language == "python":
        # Dots stay: oslo.config and oslo.messaging are separate distributions, not one "oslo".
        return re.sub(r"[-_]+", "_", name).lower()

    if language == "go":
        return name.lower()

    if language in JVM_LANGUAGES:
        return name.strip().lower()

    return npm_package_key(name)


def normalize_component(component: str) -> str:
    if not component:
        return "unknown"
    return component.strip().lower()


def _is_npm_scoped(name: str) -> bool:
    return name.startswith("@") and name.count("/") == 1


def artifact_segment(component: str) -> str:
    """Bare artifact segment with its original case; an npm ``@scope/`` belongs to the name, not a qualifier."""
    name = component.strip() if component else ""
    if ":" in name:
        name = name.rsplit(":", 1)[-1]
    elif "/" in name and not _is_npm_scoped(name):
        name = name.rsplit("/", 1)[-1]
    return name


def extract_artifact_name(component: str) -> str:
    """Bare artifact name, lowercased, for grouping and index keys."""
    return artifact_segment(component).lower() or "unknown"


def _boundary_suffixes(name: str) -> list[str]:
    """Every suffix of ``name`` that starts after a ':' or '/' boundary."""
    return [name[i + 1 :] for i, char in enumerate(name) if char in _QUALIFIER_SEPARATORS]


def _resolve_bucket(names: list[str]) -> dict[str, str]:
    """Map every name of one artifact-name bucket to its unique more-qualified spelling.

    A name attaches to a more qualified spelling of itself only when exactly one such
    candidate exists, so ``core`` is never guessed onto one of several ``*:core`` packages.
    """
    members = set(names)
    qualifiers: dict[str, list[str]] = {}
    for name in names:
        for suffix in _boundary_suffixes(name):
            if suffix in members:
                qualifiers.setdefault(suffix, []).append(name)

    # No chain can form: whatever qualifies a name's qualifier qualifies the name too.
    parent = {name: found[0] for name, found in qualifiers.items() if len(found) == 1}
    return {name: parent.get(name, name) for name in names}


def cluster_by_package_identity(components: Iterable[str]) -> dict[str, str]:
    """Map each normalized component name to the name representing its package.

    Only names where one is a qualified form of the other share a representative, so
    genuinely different packages that end in the same segment stay apart.
    """
    buckets: dict[str, dict[str, None]] = {}
    for component in components:
        normalized = normalize_component(component)
        buckets.setdefault(extract_artifact_name(normalized), {})[normalized] = None

    representative: dict[str, str] = {}
    for bucket in buckets.values():
        representative.update(_resolve_bucket(list(bucket)))
    return representative


def build_component_index(by_component: dict[str, _T]) -> dict[str, _T]:
    """Index component-keyed entries so either spelling of a package resolves.

    Dependency inventories store the bare name (Maven ``group`` sits in its own field) while an
    aggregated finding carries the qualified coordinate. Each entry gains its bare artifact name
    as an alias, but only when that name belongs to a single package, so one package's data is
    never attributed to another that ends in the same segment.

    Pair with :func:`lookup_component`; every finding/dependency name join goes through both.
    """
    owners: dict[str, list[str]] = {}
    for component in by_component:
        owners.setdefault(extract_artifact_name(component), []).append(component)

    aliased = dict(by_component)
    for artifact, components in owners.items():
        if len(components) == 1 and artifact not in aliased:
            aliased[artifact] = by_component[components[0]]
    return aliased


def lookup_component(index: Mapping[str, _T], component: str, default: _T | None = None) -> _T | None:
    """Resolve ``component`` against an index built by :func:`build_component_index`.

    The alias keys are lowercased by ``extract_artifact_name`` while real component names are
    not, so the exact spelling is tried first and the artifact name second.
    """
    found = index.get(component)
    if found is None:
        found = index.get(extract_artifact_name(component))
    return default if found is None else found


def component_match_query(component: str) -> dict[str, Any]:
    """Mongo filter matching a stored component exactly, or as a qualified form of ``component``.

    ``@scope/component`` is another npm package, not a qualified spelling, and is excluded.
    """
    escaped = re.escape(component)
    return {
        "$or": [
            {"component": component},
            {"component": {"$regex": f"^(?!@[^/:]*/{escaped}$).*[:/]{escaped}$"}},
        ]
    }


def artifact_name_expr(value: Any) -> dict[str, Any]:
    """``extract_artifact_name`` as an aggregation expression (lowercased, like the Python one)."""
    lowered = {"$toLower": value}
    return {
        "$switch": {
            "branches": [
                {
                    "case": {"$gt": [{"$indexOfCP": [lowered, ":"]}, -1]},
                    "then": {"$arrayElemAt": [{"$split": [lowered, ":"]}, -1]},
                },
                {
                    "case": {"$regexMatch": {"input": lowered, "regex": "^@[^/]*/[^/]*$"}},
                    "then": lowered,
                },
            ],
            "default": {"$arrayElemAt": [{"$split": [lowered, "/"]}, -1]},
        }
    }


def component_match_expr(name_field: Any, component_expr: Any) -> dict[str, Any]:
    """Aggregation ``$expr`` matching a dependency name against either spelling of a component.

    Unlike :func:`build_component_index` this does NOT implement the ambiguity rule: a
    bare-named dependency matches ANY same-artifact qualified component. Its only caller
    narrows the join with ``scan_id`` + ``version`` first, where prod measures no
    same-artifact/same-version collisions; a caller without that gate needs its own guard.
    """
    return {
        "$or": [
            {"$eq": [name_field, component_expr]},
            {"$eq": [{"$toLower": name_field}, artifact_name_expr(component_expr)]},
        ]
    }
