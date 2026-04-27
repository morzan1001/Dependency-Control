"""Cross-component license compatibility checking against LICENSE_INCOMPATIBILITIES."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.models.finding import Severity

from .constants import LICENSE_DATABASE, LICENSE_INCOMPATIBILITIES
from .normalizer import extract_licenses, normalize_license


def check_pair_conflict(
    a: Dict[str, str], b: Dict[str, str], seen: set
) -> Optional[Dict[str, Any]]:
    """Check if two component-license entries conflict. Returns an issue dict or None."""
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
) -> List[Dict[str, str]]:
    """Collect resolved licenses per non-dev component."""
    result: List[Dict[str, str]] = []
    for comp in components:
        comp_scope = (comp.get("scope") or "").lower()
        if ignore_dev and comp_scope in ("dev", "development", "test", "optional"):
            continue
        for lic_id, _ in extract_licenses(comp):
            normalized = normalize_license(lic_id)
            if normalized in LICENSE_DATABASE:
                result.append(
                    {
                        "component": comp.get("name", "unknown"),
                        "version": comp.get("version", "unknown"),
                        "license": normalized,
                        "purl": comp.get("purl", ""),
                    }
                )
    return result


def find_license_conflicts(
    component_licenses: List[Dict[str, str]],
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
