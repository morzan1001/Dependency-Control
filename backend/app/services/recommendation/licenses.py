from collections import defaultdict
from typing import Any, Dict, List, Optional

from app.schemas.recommendation import Priority, Recommendation, RecommendationType
from app.services.recommendation.common import get_attr, ModelOrDict

# Category restrictiveness rank (higher = more restrictive)
_CATEGORY_RANK = {
    "permissive": 0,
    "public_domain": 0,
    "weak_copyleft": 1,
    "strong_copyleft": 2,
    "network_copyleft": 3,
    "proprietary": 4,
    "unknown": -1,
}


def process_licenses(findings: List[ModelOrDict]) -> List[Recommendation]:
    """Process license compliance findings."""
    if not findings:
        return []

    # Group by license type
    by_license = defaultdict(list)
    for f in findings:
        details = get_attr(f, "details", {})
        license_name = (
            (details.get("license") if isinstance(details, dict) else None)
            or (details.get("license_id") if isinstance(details, dict) else None)
            or "unknown"
        )
        by_license[license_name].append(f)

    severity_counts: Dict[str, int] = defaultdict(int)
    components = set()

    for f in findings:
        severity_counts[get_attr(f, "severity", "UNKNOWN")] += 1
        components.add(get_attr(f, "component", "unknown"))

    # Determine priority based on findings severity
    if severity_counts.get("CRITICAL", 0) > 0:
        priority = Priority.CRITICAL
    elif severity_counts.get("HIGH", 0) > 0:
        priority = Priority.HIGH
    elif severity_counts.get("MEDIUM", 0) > 0 or severity_counts.get("LOW", 0) > 0:
        priority = Priority.MEDIUM
    else:
        # All findings are INFO-only (e.g. copyleft reduced by project context)
        priority = Priority.LOW

    problematic_licenses = list(by_license.keys())[:10]

    return [
        Recommendation(
            type=RecommendationType.LICENSE_COMPLIANCE,
            priority=priority,
            title="Resolve License Compliance Issues",
            description=(
                f"Found {len(findings)} license compliance issues across {len(components)} components. "
                f"Problematic licenses include: {', '.join(problematic_licenses[:5])}."
            ),
            impact={
                "critical": severity_counts.get("CRITICAL", 0),
                "high": severity_counts.get("HIGH", 0),
                "medium": severity_counts.get("MEDIUM", 0),
                "low": severity_counts.get("LOW", 0),
                "total": len(findings),
            },
            affected_components=list(components)[:20],
            action={
                "type": "license_compliance",
                "problematic_licenses": problematic_licenses,
                "steps": [
                    "Review license compatibility with your project's license",
                    "Consider replacing components with restrictive licenses",
                    "Consult legal team for commercial license requirements",
                    "Document license decisions and exceptions",
                ],
            },
            effort="medium",
        )
    ]


def detect_license_drift(
    current_findings: List[ModelOrDict],
    previous_findings: List[ModelOrDict],
) -> List[Recommendation]:
    """Detect license changes between scans.

    Flags components whose license changed to a more restrictive category
    (e.g. MIT → GPL) — a supply-chain risk that often goes unnoticed during
    routine dependency updates.
    """
    if not previous_findings or not current_findings:
        return []

    def _license_key(f: ModelOrDict) -> str:
        return f"{get_attr(f, 'component', '')}@{get_attr(f, 'version', '')}"

    def _license_info(f: ModelOrDict) -> Dict[str, Any]:
        details = get_attr(f, "details", {})
        return {
            "license": details.get("license", "unknown") if isinstance(details, dict) else "unknown",
            "category": details.get("category", "unknown") if isinstance(details, dict) else "unknown",
            "severity": get_attr(f, "severity", "UNKNOWN"),
        }

    # Build lookup: component@version → license info for previous scan
    prev_by_component: Dict[str, Dict[str, Any]] = {}
    for f in previous_findings:
        if get_attr(f, "type") != "license":
            continue
        key = _license_key(f)
        prev_by_component[key] = _license_info(f)

    # Find license changes (same component, different license or stricter category)
    drifted: List[Dict[str, Any]] = []
    for f in current_findings:
        if get_attr(f, "type") != "license":
            continue
        key = _license_key(f)
        prev = prev_by_component.get(key)
        if not prev:
            continue

        curr_info = _license_info(f)
        if curr_info["license"] == prev["license"]:
            continue

        # License changed — check if it became more restrictive
        prev_rank = _CATEGORY_RANK.get(prev["category"], -1)
        curr_rank = _CATEGORY_RANK.get(curr_info["category"], -1)

        if curr_rank > prev_rank:
            drifted.append(
                {
                    "component": get_attr(f, "component", "unknown"),
                    "version": get_attr(f, "version", "unknown"),
                    "previous_license": prev["license"],
                    "previous_category": prev["category"],
                    "current_license": curr_info["license"],
                    "current_category": curr_info["category"],
                }
            )

    if not drifted:
        return []

    # Determine priority based on how restrictive the drift is
    has_copyleft_drift = any(_CATEGORY_RANK.get(d["current_category"], 0) >= 2 for d in drifted)

    return [
        Recommendation(
            type=RecommendationType.LICENSE_DRIFT,
            priority=Priority.HIGH if has_copyleft_drift else Priority.MEDIUM,
            title=f"License drift detected: {len(drifted)} component(s) changed to more restrictive licenses",
            description=(
                "The following dependencies changed their license to a more restrictive "
                "category compared to the previous scan. This may introduce new compliance "
                "obligations and should be reviewed."
            ),
            impact={
                "total": len(drifted),
                "copyleft_drift": len([d for d in drifted if _CATEGORY_RANK.get(d["current_category"], 0) >= 2]),
            },
            affected_components=[
                f"{d['component']}@{d['version']}: {d['previous_license']} → {d['current_license']}"
                for d in drifted[:15]
            ],
            action={
                "type": "review_license_drift",
                "drifted_components": drifted[:20],
                "steps": [
                    "Review the license change for each affected component",
                    "Check if the new license is compatible with your project",
                    "Consider pinning the previous version if the new license is problematic",
                    "Update license waivers if needed",
                ],
            },
            effort="medium",
        )
    ]
