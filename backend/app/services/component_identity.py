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
    language = raw.strip().lower()
    language = _CALLGRAPH_LANGUAGE_ALIASES.get(language, language)
    if language not in _CALLGRAPH_LANGUAGES:
        supported = ", ".join(sorted(_CALLGRAPH_LANGUAGES))
        raise ValueError(f"unsupported callgraph language '{raw}'; supported: {supported}")
    return language


def canonical_module_key(name: str, language: str) -> str:
    """The single meeting point between callgraph parsers (stored keys) and reachability enrichment (lookup keys)."""
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
    """An npm @scope/ belongs to the name, not a qualifier."""
    name = component.strip() if component else ""
    if ":" in name:
        name = name.rsplit(":", 1)[-1]
    elif "/" in name and not _is_npm_scoped(name):
        name = name.rsplit("/", 1)[-1]
    return name


def component_name_candidates(component: str) -> list[str]:
    return list(dict.fromkeys((component, artifact_segment(component))))


def extract_artifact_name(component: str) -> str:
    return artifact_segment(component).lower() or "unknown"


def _boundary_suffixes(name: str) -> list[str]:
    return [name[i + 1 :] for i, char in enumerate(name) if char in _QUALIFIER_SEPARATORS]


def _resolve_bucket(names: list[str]) -> dict[str, str]:
    """A name attaches only to a unique more-qualified spelling, so core is never guessed onto one of several *:core."""
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
    """Only qualified forms of one another share a representative, so different packages ending alike stay apart."""
    buckets: dict[str, dict[str, None]] = {}
    for component in components:
        normalized = normalize_component(component)
        buckets.setdefault(extract_artifact_name(normalized), {})[normalized] = None

    representative: dict[str, str] = {}
    for bucket in buckets.values():
        representative.update(_resolve_bucket(list(bucket)))
    return representative


def build_component_index(by_component: dict[str, _T]) -> dict[str, _T]:
    """Bare-name aliases are added only for a single package; pair with lookup_component for every name join."""
    owners: dict[str, list[str]] = {}
    for component in by_component:
        owners.setdefault(extract_artifact_name(component), []).append(component)

    aliased = dict(by_component)
    for artifact, components in owners.items():
        if len(components) == 1:
            key = _qualified_alias(artifact) if _is_qualified(components[0]) else artifact
            aliased.setdefault(key, by_component[components[0]])
    return aliased


def _is_qualified(component: str) -> bool:
    return artifact_segment(component) != component.strip()


def _qualified_alias(artifact: str) -> str:
    # Outside the keys a qualified name's artifact lookup tries, so x/foo/v2 never resolves to y/bar/v2.
    return f":{artifact}"


def lookup_component(index: Mapping[str, _T], component: str, default: _T | None = None) -> _T | None:
    """Exact spelling first: alias keys are lowercased while real component names are not."""
    found = index.get(component)
    if found is None:
        artifact = extract_artifact_name(component)
        found = index.get(artifact)
        if found is None and not _is_qualified(component):
            found = index.get(_qualified_alias(artifact))
    return default if found is None else found


def component_match_query(component: str) -> dict[str, Any]:
    """@scope/component is another npm package, not a qualified form."""
    escaped = re.escape(component)
    return {
        "$or": [
            {"component": component},
            {"component": {"$regex": f"^(?!@[^/:]*/{escaped}$).*[:/]{escaped}$"}},
        ]
    }


def artifact_name_expr(value: Any) -> dict[str, Any]:
    """Must stay equivalent to extract_artifact_name."""
    name = "$$artifact_name"
    segment = {
        "$switch": {
            "branches": [
                {
                    "case": {"$gt": [{"$indexOfCP": [name, ":"]}, -1]},
                    "then": {"$arrayElemAt": [{"$split": [name, ":"]}, -1]},
                },
                {"case": {"$regexMatch": {"input": name, "regex": "^@[^/]*/[^/]*$"}}, "then": name},
            ],
            "default": {"$arrayElemAt": [{"$split": [name, "/"]}, -1]},
        }
    }
    return {
        "$let": {
            "vars": {"artifact_name": {"$toLower": {"$trim": {"input": {"$ifNull": [value, ""]}}}}},
            "in": {
                "$let": {
                    "vars": {"artifact_segment": segment},
                    "in": {"$cond": [{"$eq": ["$$artifact_segment", ""]}, "unknown", "$$artifact_segment"]},
                }
            },
        }
    }


def component_match_expr(name_field: Any, component_expr: Any) -> dict[str, Any]:
    """No ambiguity rule: a bare name matches any same-artifact component, so narrow by scan_id and version first."""
    return {
        "$or": [
            {"$eq": [name_field, component_expr]},
            {"$eq": [{"$toLower": name_field}, artifact_name_expr(component_expr)]},
        ]
    }
