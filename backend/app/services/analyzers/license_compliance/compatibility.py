"""Cross-component license compatibility checking against LICENSE_INCOMPATIBILITIES."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.models.finding import Severity
from app.models.license import LicenseCategory

from .constants import LICENSE_DATABASE, LICENSE_INCOMPATIBILITIES
from .normalizer import (
    extract_licenses,
    has_spdx_expression,
    normalize_license,
    parse_spdx_expression,
)

# Restrictiveness ordering used to pick the least-restrictive OR alternative,
# mirroring analyzer._track_expression_stats / _evaluate_expression so both
# passes agree on which alternative a dual-licensed component resolves to.
_CATEGORY_RANK: Dict[LicenseCategory, int] = {
    LicenseCategory.PERMISSIVE: 0,
    LicenseCategory.PUBLIC_DOMAIN: 0,
    LicenseCategory.WEAK_COPYLEFT: 1,
    LicenseCategory.STRONG_COPYLEFT: 2,
    LicenseCategory.NETWORK_COPYLEFT: 3,
    LicenseCategory.PROPRIETARY: 4,
}


def _least_restrictive_group(or_groups: List[List[str]]) -> List[str]:
    """Pick the OR-alternative with the lowest restrictiveness.

    Within an alternative, AND-connected licenses all apply, so the group's
    rank is its most-restrictive member. Across alternatives, the consumer may
    choose freely, so we keep the least-restrictive group.
    """
    best_rank: Optional[int] = None
    best_group: List[str] = []
    for group in or_groups:
        worst_rank = 0
        for lic_id in group:
            info = LICENSE_DATABASE.get(normalize_license(lic_id))
            if info:
                worst_rank = max(worst_rank, _CATEGORY_RANK.get(info.category, 5))
        if best_rank is None or worst_rank < best_rank:
            best_rank = worst_rank
            best_group = group
    return best_group


def _resolve_component_license_ids(comp: Dict[str, Any]) -> List[str]:
    """Return the license IDs that actually apply to a component.

    SPDX OR-expressions are resolved to a single chosen alternative (the least
    restrictive), matching analyzer._analyze_component. Without an OR-expression
    the component's flat license list applies (AND / comma / multiple entries).
    """
    spdx_expr = has_spdx_expression(comp)
    if spdx_expr:
        or_groups = parse_spdx_expression(spdx_expr)
        return _least_restrictive_group(or_groups)
    return [lic_id for lic_id, _ in extract_licenses(comp)]


def check_pair_conflict(a: Dict[str, Any], b: Dict[str, Any], seen: set) -> Optional[Dict[str, Any]]:
    """Check if two component-license entries conflict. Returns an issue dict or None."""
    # Licenses drawn from the same component never conflict with each other
    # (e.g. AND-combined licenses in one package are a packaging reality, not a
    # cross-component incompatibility).
    if a.get("component_id") is not None and a.get("component_id") == b.get("component_id"):
        return None

    if a["license"] == b["license"]:
        return None

    pair = tuple(sorted([a["license"], b["license"]]))
    if pair in seen:
        return None

    explanation = LICENSE_INCOMPATIBILITIES.get((a["license"], b["license"])) or LICENSE_INCOMPATIBILITIES.get(
        (b["license"], a["license"])
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
    components: List[Dict[str, Any]],
    ignore_dev: bool,
) -> List[Dict[str, Any]]:
    """Collect resolved licenses per non-dev component."""
    result: List[Dict[str, Any]] = []
    for idx, comp in enumerate(components):
        comp_scope = (comp.get("scope") or "").lower()
        if ignore_dev and comp_scope in ("dev", "development", "test", "optional"):
            continue
        for lic_id in _resolve_component_license_ids(comp):
            normalized = normalize_license(lic_id)
            if normalized in LICENSE_DATABASE:
                result.append(
                    {
                        "component": comp.get("name", "unknown"),
                        "version": comp.get("version", "unknown"),
                        "license": normalized,
                        "purl": comp.get("purl", ""),
                        "component_id": idx,
                    }
                )
    return result


def find_license_conflicts(
    component_licenses: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Find known incompatibilities between license pairs."""
    issues: List[Dict[str, Any]] = []
    seen_conflicts: set = set()

    for i, a in enumerate(component_licenses):
        for b in component_licenses[i + 1 :]:
            conflict = check_pair_conflict(a, b, seen_conflicts)
            if conflict:
                issues.append(conflict)

    return issues


def check_license_compatibility(
    components: List[Dict[str, Any]],
    ignore_dev: bool,
) -> List[Dict[str, Any]]:
    """Check for known license incompatibilities across all components."""
    component_licenses = collect_component_licenses(components, ignore_dev)
    return find_license_conflicts(component_licenses)
