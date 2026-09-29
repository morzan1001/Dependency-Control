"""Cross-component license compatibility checking against LICENSE_INCOMPATIBILITIES."""

from __future__ import annotations

from typing import Any

from app.core.constants import NON_RUNTIME_SCOPES
from app.models.finding import Severity
from app.models.license import CATEGORY_RESTRICTIVENESS

from .constants import (
    CANONICAL_LICENSE_ID,
    LICENSE_DATABASE,
    LICENSE_INCOMPATIBILITIES,
)
from .normalizer import parse_license_expression


def partition_or_groups(or_groups: list[list[str]]) -> tuple[list[list[str]], list[str]]:
    """Split OR-alternatives into readable ones, as database ids, and the unknown ids that made the rest unreadable."""
    readable: list[list[str]] = []
    unreadable: list[str] = []
    for group in or_groups:
        # A WITH exception only grants more, so the licence it modifies decides the verdict.
        ids = list(dict.fromkeys(member.partition(" WITH ")[0] for member in group))
        # AND binds every member, so one unrecognised member leaves the whole alternative unreadable.
        missing = [lic for lic in ids if lic not in LICENSE_DATABASE]
        if missing:
            unreadable.extend(lic for lic in missing if lic not in unreadable)
        else:
            readable.append(ids)
    return readable, unreadable


def least_restrictive_group(or_groups: list[list[str]]) -> list[str]:
    """Pick the lowest-restrictiveness readable OR-alternative, ranked by its most-restrictive AND-member."""
    readable, _ = partition_or_groups(or_groups)
    return min(
        readable,
        key=lambda group: max(CATEGORY_RESTRICTIVENESS[LICENSE_DATABASE[lic].category] for lic in group),
        default=[],
    )


def _resolve_component_license_ids(comp: dict[str, Any]) -> list[str]:
    """Return the license IDs that apply, resolving OR-expressions to the least-restrictive alternative."""
    groups = parse_license_expression(comp.get("license") or "")
    if len(groups) > 1:
        return least_restrictive_group(groups)
    return [member.partition(" WITH ")[0] for group in groups for member in group]


def check_pair_conflict(a: dict[str, Any], b: dict[str, Any], seen: set) -> dict[str, Any] | None:
    """Check if two component-license entries conflict. Returns an issue dict or None."""
    # Licenses from the same component are a packaging reality, not a cross-component conflict.
    if a.get("component_id") is not None and a.get("component_id") == b.get("component_id"):
        return None

    if a["license"] == b["license"]:
        return None

    pair = tuple(sorted([a["license"], b["license"]]))
    if pair in seen:
        return None

    explanation = LICENSE_INCOMPATIBILITIES.get(
        frozenset(
            {CANONICAL_LICENSE_ID.get(a["license"], a["license"]), CANONICAL_LICENSE_ID.get(b["license"], b["license"])}
        )
    )
    if not explanation:
        return None

    seen.add(pair)
    return {
        "component": f"{a['component']} + {b['component']}",
        "version": f"{a['version']} / {b['version']}",
        "license": f"{a['license']} / {b['license']}",
        "license_url": None,
        "severity": Severity.HIGH.value,
        "category": "license_incompatibility",
        "message": f"License conflict: {a['license']} and {b['license']}",
        "explanation": (
            f"{explanation}\n\n"
            f"Component A: {a['component']}@{a['version']} ({a['license']})\n"
            f"Component B: {b['component']}@{b['version']} ({b['license']})"
        ),
        "recommendation": (
            "These licenses cannot coexist in the same distributed work. Options:\n"
            "• Replace one of the conflicting components with an alternative\n"
            "• Check if a dual-licensed or 'or-later' variant resolves the conflict\n"
            "• Isolate the components into separate processes/services"
        ),
        "obligations": [],
        "risks": [explanation],
        "purl": a["purl"],
    }


def collect_component_licenses(
    components: list[dict[str, Any]],
    ignore_dev: bool,
) -> list[dict[str, Any]]:
    """Collect resolved licenses per non-dev component."""
    result: list[dict[str, Any]] = []
    for idx, comp in enumerate(components):
        if ignore_dev and (comp.get("scope") or "").lower() in NON_RUNTIME_SCOPES:
            continue
        result.extend(
            {
                "component": comp.get("name", "unknown"),
                "version": comp.get("version", "unknown"),
                "license": lic_id,
                "purl": comp.get("purl", ""),
                "component_id": idx,
            }
            for lic_id in _resolve_component_license_ids(comp)
            if lic_id in LICENSE_DATABASE
        )
    return result


def find_license_conflicts(
    component_licenses: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Find known incompatibilities between license pairs."""
    issues: list[dict[str, Any]] = []
    seen_conflicts: set = set()

    for i, a in enumerate(component_licenses):
        for b in component_licenses[i + 1 :]:
            conflict = check_pair_conflict(a, b, seen_conflicts)
            if conflict:
                issues.append(conflict)

    return issues


def check_license_compatibility(
    components: list[dict[str, Any]],
    ignore_dev: bool,
) -> list[dict[str, Any]]:
    """Check for known license incompatibilities across all components."""
    component_licenses = collect_component_licenses(components, ignore_dev)
    return find_license_conflicts(component_licenses)
