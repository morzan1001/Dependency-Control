from collections.abc import Iterable
from typing import Any

from app.core.purl import package_identity
from app.models.finding import Severity
from app.models.license import CATEGORY_RESTRICTIVENESS, LicenseCategory
from app.schemas.recommendation import Effort, Priority, Recommendation, RecommendationType
from app.services.analyzers.license_compliance.constants import UNDETERMINED_LICENSE_ID
from app.services.recommendation.common import (
    AFFECTED_COMPONENTS_SHOWN,
    ModelOrDict,
    get_attr,
    name_some,
    sample_components,
    sampled,
    severity_impact,
)

_LICENSES_NAMED = 5

# Drift into strong copyleft or anything more restrictive (network copyleft, proprietary) is urgent.
_HIGH_PRIORITY_DRIFT_MIN_RANK = CATEGORY_RESTRICTIVENESS[LicenseCategory.STRONG_COPYLEFT]


def process_licenses(findings: list[ModelOrDict]) -> list[Recommendation]:
    """License compliance card over the findings the project policy did not accept."""
    severities = []
    components = set()
    licenses = set()
    for f in findings:
        severity = get_attr(f, "severity", "UNKNOWN")
        license_name = get_attr(f, "details", {}).get("license") or "unknown"
        # The evaluator marks a policy-accepted outcome INFO; an undeterminable licence is INFO yet needs action.
        if severity == Severity.INFO and license_name != UNDETERMINED_LICENSE_ID:
            continue
        severities.append(severity)
        components.add(get_attr(f, "component", "unknown"))
        licenses.add(license_name)

    impact = severity_impact(severities)
    if not impact["total"]:
        return []

    if impact["critical"]:
        priority = Priority.CRITICAL
    elif impact["high"]:
        priority = Priority.HIGH
    elif impact["medium"] or impact["low"]:
        priority = Priority.MEDIUM
    else:
        # Only undeterminable licences remain.
        priority = Priority.LOW

    problematic_licenses = sorted(licenses)
    components_shown, components_total = sample_components(sorted(components))

    return [
        Recommendation(
            type=RecommendationType.LICENSE_COMPLIANCE,
            priority=priority,
            title="Resolve License Compliance Issues",
            description=(
                f"Found {impact['total']} license compliance issues across {len(components)} components. "
                f"Problematic licenses: {name_some(problematic_licenses, _LICENSES_NAMED)}."
            ),
            impact=impact,
            affected_components=components_shown,
            affected_components_total=components_total,
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
            effort=Effort.MEDIUM,
        )
    ]


def _most_restrictive_by_package(dependencies: Iterable[ModelOrDict]) -> dict[tuple[str, str], tuple[int, ModelOrDict]]:
    """Per version-free package, the dependency with the highest known licence category and its rank."""
    by_package: dict[tuple[str, str], tuple[int, ModelOrDict]] = {}
    for dep in dependencies:
        rank = CATEGORY_RESTRICTIVENESS.get(get_attr(dep, "license_category"), -1)
        # An unknown or missing category is not comparable: a licence that became determinable did not change.
        if rank < 0:
            continue
        key = package_identity(get_attr(dep, "purl"), get_attr(dep, "name") or "", None, None)
        if key not in by_package or rank > by_package[key][0]:
            by_package[key] = (rank, dep)
    return by_package


def detect_license_drift(
    current_dependencies: Iterable[ModelOrDict],
    previous_dependencies: Iterable[ModelOrDict],
) -> list[Recommendation]:
    """Flag packages whose licence moved to a more restrictive category since the previous scan (e.g. MIT → GPL)."""
    previous = _most_restrictive_by_package(previous_dependencies)
    drifted: list[dict[str, Any]] = []
    for key, (rank, dep) in _most_restrictive_by_package(current_dependencies).items():
        if key not in previous or rank <= previous[key][0]:
            continue
        before = previous[key][1]
        drifted.append(
            {
                "component": get_attr(dep, "name"),
                "previous_license": get_attr(before, "license"),
                "previous_category": get_attr(before, "license_category"),
                "current_license": get_attr(dep, "license"),
                "current_category": get_attr(dep, "license_category"),
            }
        )

    if not drifted:
        return []

    restrictive = [
        d for d in drifted if CATEGORY_RESTRICTIVENESS[d["current_category"]] >= _HIGH_PRIORITY_DRIFT_MIN_RANK
    ]
    drift_shown, drift_total = sample_components(
        f"{d['component']}: {d['previous_license']} → {d['current_license']}" for d in drifted
    )

    return [
        Recommendation(
            type=RecommendationType.LICENSE_DRIFT,
            priority=Priority.HIGH if restrictive else Priority.MEDIUM,
            title=f"License drift detected: {len(drifted)} component(s) changed to more restrictive licenses",
            description=(
                "The following dependencies changed their license to a more restrictive "
                "category compared to the previous scan. This may introduce new compliance "
                "obligations and should be reviewed."
            ),
            impact={
                "total": len(drifted),
                "restrictive_drift": len(restrictive),
            },
            affected_components=drift_shown,
            affected_components_total=drift_total,
            action={
                "type": "review_license_drift",
                **sampled("drifted_components", drifted, AFFECTED_COMPONENTS_SHOWN),
                "steps": [
                    "Review the license change for each affected component",
                    "Check if the new license is compatible with your project",
                    "Consider pinning the previous version if the new license is problematic",
                    "Update license waivers if needed",
                ],
            },
            effort=Effort.MEDIUM,
        )
    ]
