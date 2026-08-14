"""Stateless component-name helpers used during aggregation."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeVar

_QUALIFIER_SEPARATORS = (":", "/")

_T = TypeVar("_T")


def normalize_component(component: str) -> str:
    if not component:
        return "unknown"
    return component.strip().lower()


def extract_artifact_name(component: str) -> str:
    """Extract the bare artifact name from Maven-style or scoped component names for grouping."""
    name = component.lower().strip() if component else "unknown"
    if ":" in name:
        name = name.rsplit(":", 1)[-1]
    elif "/" in name:
        name = name.rsplit("/", 1)[-1]
    return name or "unknown"


def is_qualified_form(qualified: str, bare: str) -> bool:
    """True if ``qualified`` is ``bare`` prefixed by a group/scope on a ':' or '/' boundary."""
    q, b = normalize_component(qualified), normalize_component(bare)
    return q != b and any(q.endswith(sep + b) for sep in _QUALIFIER_SEPARATORS)


def _resolve_bucket(names: list[str]) -> dict[str, str]:
    """Map every name of one artifact-name bucket to the most qualified name it belongs to.

    A name attaches to a more qualified spelling of itself only when exactly one such
    candidate exists, so ``core`` is never guessed onto one of several ``*/core`` packages.
    """
    parent: dict[str, str] = {}
    for name in names:
        qualifiers = [other for other in names if is_qualified_form(other, name)]
        if len(qualifiers) == 1:
            parent[name] = qualifiers[0]

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


def add_artifact_name_aliases(by_component: dict[str, _T]) -> dict[str, _T]:
    """Expose each entry additionally under its bare artifact name when that name is unambiguous.

    Dependency inventories store the bare name (Maven ``group`` sits in its own field) while an
    aggregated finding carries the qualified coordinate; the alias lets that join resolve without
    attributing one package's findings to another that ends in the same segment.
    """
    owners: dict[str, list[str]] = {}
    for component in by_component:
        owners.setdefault(extract_artifact_name(component), []).append(component)

    aliased = dict(by_component)
    for artifact, components in owners.items():
        if len(components) == 1 and artifact not in aliased:
            aliased[artifact] = by_component[components[0]]
    return aliased
