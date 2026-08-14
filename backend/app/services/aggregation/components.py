"""Stateless component-name helpers used during aggregation."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, TypeVar

_QUALIFIER_SEPARATORS = (":", "/")

_T = TypeVar("_T")


def normalize_component(component: str) -> str:
    if not component:
        return "unknown"
    return component.strip().lower()


def artifact_segment(component: str) -> str:
    """Bare artifact segment with its original case, for matching case-sensitive stored names."""
    name = component.strip() if component else ""
    if ":" in name:
        name = name.rsplit(":", 1)[-1]
    elif "/" in name:
        name = name.rsplit("/", 1)[-1]
    return name


def extract_artifact_name(component: str) -> str:
    """Bare artifact name, lowercased, for grouping and index keys."""
    return artifact_segment(component).lower() or "unknown"


def _boundary_suffixes(name: str) -> list[str]:
    """Every suffix of ``name`` that starts after a ':' or '/' boundary."""
    return [name[i + 1 :] for i, char in enumerate(name) if char in _QUALIFIER_SEPARATORS]


def _resolve_bucket(names: list[str]) -> dict[str, str]:
    """Map every name of one artifact-name bucket to the most qualified name it belongs to.

    A name attaches to a more qualified spelling of itself only when exactly one such
    candidate exists, so ``core`` is never guessed onto one of several ``*/core`` packages.
    """
    # Walking each name's own boundary suffixes keeps this linear; a bucket can hold every
    # file sharing a basename in a large SAST scan, where pairwise matching would not scale.
    members = set(names)
    qualifiers: dict[str, list[str]] = {}
    for name in names:
        for suffix in _boundary_suffixes(name):
            if suffix != name and suffix in members:
                qualifiers.setdefault(suffix, []).append(name)

    parent: dict[str, str] = {name: found[0] for name, found in qualifiers.items() if len(found) == 1}

    resolved: dict[str, str] = {}
    for name in names:
        seen = {name}
        current = name
        while (nxt := parent.get(current)) is not None and nxt not in seen:
            seen.add(nxt)
            current = nxt
        resolved[name] = current
    return resolved


def cluster_by_package_identity(components: Iterable[str]) -> dict[str, str]:
    """Map each normalized component name to the name representing its package.

    Only names where one is a qualified form of the other share a representative, so
    genuinely different packages that end in the same segment stay apart.
    """
    buckets: dict[str, list[str]] = {}
    for component in components:
        normalized = normalize_component(component)
        bucket = buckets.setdefault(extract_artifact_name(normalized), [])
        if normalized not in bucket:
            bucket.append(normalized)

    representative: dict[str, str] = {}
    for bucket in buckets.values():
        representative.update(_resolve_bucket(bucket))
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
    """Mongo filter matching a stored component exactly, or as a qualified form of ``component``."""
    return {
        "$or": [
            {"component": component},
            {"component": {"$regex": f"[:/]{re.escape(component)}$"}},
        ]
    }


def artifact_name_expr(value: Any) -> dict[str, Any]:
    """``extract_artifact_name`` as an aggregation expression (lowercased, like the Python one)."""
    lowered = {"$toLower": value}
    return {
        "$cond": [
            {"$gt": [{"$indexOfCP": [lowered, ":"]}, -1]},
            {"$arrayElemAt": [{"$split": [lowered, ":"]}, -1]},
            {"$arrayElemAt": [{"$split": [lowered, "/"]}, -1]},
        ]
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
