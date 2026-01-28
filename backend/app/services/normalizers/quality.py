from typing import Any, Dict, List, Optional, TYPE_CHECKING

from app.models.finding import Finding, FindingType, Severity
from app.services.normalizers.utils import build_finding_id, safe_get, safe_severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator


def normalize_scorecard(
    aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None
):
    """
    Process OpenSSF Scorecard results and package metadata from deps_dev scanner.
    Also stores scorecard data for component enrichment.
    """
    # Process package metadata (not findings, but enrichment data)
    for key, metadata in (result.get("package_metadata") or {}).items():
        # Populate the DependencyEnrichment structure
        name = metadata.get("name", "")
        version = metadata.get("version", "")
        if name and version:
            aggregator.enrich_from_deps_dev(name, version, metadata)

    # Process scorecard issues (these become findings)
    for item in result.get("scorecard_issues") or []:
        scorecard = item.get("scorecard") or {}
        overall = scorecard.get("overallScore", 0)
        failed_checks: List[Dict[str, Any]] = item.get("failed_checks") or []
        critical_issues: List[str] = item.get("critical_issues") or []
        project_url = item.get("project_url") or ""
        component = safe_get(item, "component", "unknown")
        version = item.get("version") or ""

        # Store scorecard data for component enrichment
        component_key = f"{component}@{version}" if version else component

        # Store in aggregator's scorecard cache (use public method if available)
        scorecard_data = {
            "overall_score": overall,
            "failed_checks": failed_checks,
            "critical_issues": critical_issues,
            "project_url": project_url,
            "checks": scorecard.get("checks") or [],
        }

        # Use public property if available, otherwise fall back to private
        if hasattr(aggregator, "scorecard_cache"):
            aggregator.scorecard_cache[component_key] = scorecard_data
        elif hasattr(aggregator, "_scorecard_cache"):
            aggregator._scorecard_cache[component_key] = scorecard_data

        # Determine severity based on score and critical issues
        if (
            overall < 3.0
            or "Maintained" in critical_issues
            or "Vulnerabilities" in critical_issues
        ):
            severity = Severity.HIGH
        elif overall < 5.0 or critical_issues:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # Build detailed description
        description_parts = [f"OpenSSF Scorecard score: {overall:.1f}/10"]

        if critical_issues:
            description_parts.append(f"Critical issues: {', '.join(critical_issues)}")

        if failed_checks:
            failed_names = [
                f"{c.get('name', '?')} ({c.get('score', 0)}/10)"
                for c in failed_checks[:3]
            ]
            description_parts.append(f"Failed checks: {', '.join(failed_names)}")
            if len(failed_checks) > 3:
                description_parts[-1] += f" (+{len(failed_checks) - 3} more)"

        description = ". ".join(description_parts)

        # Build recommendation based on issues
        recommendations: List[str] = []
        for check in failed_checks:
            check_name = check.get("name", "")
            if check_name == "Maintained":
                recommendations.append(
                    "Consider finding an actively maintained alternative"
                )
            elif check_name == "Vulnerabilities":
                recommendations.append("Check for and apply security patches")
            elif check_name == "CII-Best-Practices":
                recommendations.append("Package doesn't follow OpenSSF best practices")
            elif check_name == "Code-Review":
                recommendations.append(
                    "Limited code review process - higher risk of unreviewed changes"
                )
            elif check_name == "Fuzzing":
                recommendations.append("No fuzzing - potential undiscovered bugs")
            elif check_name == "SAST":
                recommendations.append(
                    "No static analysis - potential code quality issues"
                )

        aggregator.add_finding(
            Finding(
                id=build_finding_id("SCORECARD", component),
                type=FindingType.QUALITY,
                severity=severity,
                component=component,
                version=version,
                description=description,
                scanners=["deps_dev"],
                details={
                    "scorecard": scorecard,
                    "overall_score": overall,
                    "failed_checks": failed_checks,
                    "critical_issues": critical_issues,
                    "project_url": project_url,
                    "repository": scorecard.get("repository"),
                    "scorecard_date": scorecard.get("date"),
                    "recommendation": (
                        " • ".join(recommendations) if recommendations else None
                    ),
                    "checks_summary": {
                        check.get("name"): check.get("score")
                        for check in (scorecard.get("checks") or [])
                        if check.get("score", -1) >= 0
                    },
                },
            ),
            source=source,
        )


def normalize_typosquatting(
    aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None
):
    """Normalize typosquatting detection findings."""
    for item in result.get("typosquatting_issues") or []:
        similarity = item.get("similarity", 0)
        imitated = item.get("imitated_package") or "unknown"
        component = safe_get(item, "component", "unknown")

        aggregator.add_finding(
            Finding(
                id=build_finding_id("TYPO", component),
                type=FindingType.MALWARE,  # Typosquatting is a form of malware/attack
                severity=Severity.CRITICAL,
                component=component,
                version=item.get("version"),
                description=(
                    f"Possible typosquatting detected! '{component}' is "
                    f"{similarity*100:.1f}% similar to popular package '{imitated}'"
                ),
                scanners=["typosquatting"],
                details={"imitated_package": imitated, "similarity": similarity},
            ),
            source=source,
        )


def normalize_maintainer_risk(
    aggregator: "ResultAggregator", result: Dict[str, Any], source: Optional[str] = None
):
    """Normalize maintainer risk results into findings."""
    for item in result.get("maintainer_issues") or []:
        risks: List[Dict[str, Any]] = item.get("risks") or []
        component = safe_get(item, "component", "unknown")

        # Create a combined description from all risks
        risk_messages = [r.get("message", "") for r in risks if r.get("message")]
        description = (
            "; ".join(risk_messages) if risk_messages else "Maintainer risk detected"
        )

        aggregator.add_finding(
            Finding(
                id=build_finding_id("MAINT", component),
                type=FindingType.QUALITY,  # Supply chain quality issue
                severity=safe_severity(item.get("severity"), default=Severity.MEDIUM),
                component=component,
                version=item.get("version"),
                description=description,
                scanners=["maintainer_risk"],
                details={
                    "risks": risks,
                    "maintainer_info": item.get("maintainer_info") or {},
                    "risk_count": len(risks),
                },
            ),
            source=source,
        )
