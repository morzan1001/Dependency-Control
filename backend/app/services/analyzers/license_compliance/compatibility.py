"""Cross-component license compatibility checking against LICENSE_INCOMPATIBILITIES."""

from __future__ import annotations

from typing import Any

from app.models.finding import Severity

from .constants import (
    CATEGORY_RESTRICTIVENESS,
    LICENSE_DATABASE,
    LICENSE_INCOMPATIBILITIES,
)
from .normalizer import (
    extract_licenses,
    has_spdx_expression,
    normalize_license,
    parse_spdx_expression,
)


def least_restrictive_group(or_groups: list[list[str]]) -> list[str]:
    """Pick the OR-alternative with the lowest restrictiveness (ranked by its most-restrictive AND-member)."""
    best_rank: int | None = None
    best_group: list[str] = []
    for group in or_groups:
        worst_rank = 0
        for lic_id in group:
            info = LICENSE_DATABASE.get(normalize_license(lic_id))
            if info:
                worst_rank = max(worst_rank, CATEGORY_RESTRICTIVENESS.get(info.category, 5))
        if best_rank is None or worst_rank < best_rank:
            best_rank = worst_rank
            best_group = group
    return best_group


def _resolve_component_license_ids(comp: dict[str, Any]) -> list[str]:
    """Return the license IDs that apply, resolving OR-expressions to the least-restrictive alternative."""
    spdx_expr = has_spdx_expression(comp)
    if spdx_expr:
        or_groups = parse_spdx_expression(spdx_expr)
        return least_restrictive_group(or_groups)
    return [lic_id for lic_id, _ in extract_licenses(comp)]


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
    components: list[dict[str, Any]],
    ignore_dev: bool,
) -> list[dict[str, Any]]:
    """Collect resolved licenses per non-dev component."""
    result: list[dict[str, Any]] = []
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
