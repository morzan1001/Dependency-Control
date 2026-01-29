from collections import defaultdict
from typing import Any, Dict, List

from app.schemas.recommendation import Priority, Recommendation, RecommendationType
from app.services.recommendation.common import get_attr, ModelOrDict


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
    else:
        priority = Priority.MEDIUM

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
