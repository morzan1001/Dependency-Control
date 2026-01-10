from typing import Any, Dict, TYPE_CHECKING
from app.models.finding import Finding, FindingType, Severity

if TYPE_CHECKING:
    from app.services.aggregator import ResultAggregator

def normalize_scorecard(aggregator: "ResultAggregator", result: Dict[str, Any], source: str = None):
    """
    Process OpenSSF Scorecard results and package metadata from deps_dev scanner.
    Also stores scorecard data for component enrichment.
    """
    # Process package metadata (not findings, but enrichment data)
    for key, metadata in result.get("package_metadata", {}).items():
        # Populate the DependencyEnrichment structure
        name = metadata.get("name", "")
        version = metadata.get("version", "")
        if name and version:
            aggregator.enrich_from_deps_dev(name, version, metadata)

    # Process scorecard issues (these become findings)
    for item in result.get("scorecard_issues", []):
        scorecard = item.get("scorecard", {})
        overall = scorecard.get("overallScore", 0)
        failed_checks = item.get("failed_checks", [])
        critical_issues = item.get("critical_issues", [])
        project_url = item.get("project_url", "")
        component = item.get("component", "")
        version = item.get("version", "")

        # Store scorecard data for component enrichment
        # This allows other findings to reference scorecard data
        component_key = f"{component}@{version}" if version else component
        
        # Access cache directly via private member (or public if we open it)
        # Using public property would be better if available
        if hasattr(aggregator, 'scorecard_cache'):
            aggregator.scorecard_cache[component_key] = {
                "overall_score": overall,
                "failed_checks": failed_checks,
                "critical_issues": critical_issues,
                "project_url": project_url,
                "checks": scorecard.get("checks", []),
            }
        else:
            # Fallback to direct access if property not renamed yet
            aggregator._scorecard_cache[component_key] = {
                "overall_score": overall,
                "failed_checks": failed_checks,
                "critical_issues": critical_issues,
                "project_url": project_url,
                "checks": scorecard.get("checks", []),
            }

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
            description_parts.append(
                f"Critical issues: {', '.join(critical_issues)}"
            )

        if failed_checks:
            failed_names = [
                f"{c['name']} ({c['score']}/10)" for c in failed_checks[:3]
            ]
            description_parts.append(f"Failed checks: {', '.join(failed_names)}")
            if len(failed_checks) > 3:
                description_parts[-1] += f" (+{len(failed_checks) - 3} more)"

        description = ". ".join(description_parts)

        # Build recommendation based on issues
        recommendations = []
        for check in failed_checks:
            check_name = check.get("name", "")
            if check_name == "Maintained":
                recommendations.append(
                    "Consider finding an actively maintained alternative"
                )
            elif check_name == "Vulnerabilities":
                recommendations.append("Check for and apply security patches")
            elif check_name == "CII-Best-Practices":
                recommendations.append(
                    "Package doesn't follow OpenSSF best practices"
                )
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
                id=f"SCORECARD-{component}",
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
                        for check in scorecard.get("checks", [])
                        if check.get("score", -1) >= 0
                    },
                },
            ),
            source=source,
        )

def normalize_typosquatting(aggregator: "ResultAggregator", result: Dict[str, Any], source: str = None):
    for item in result.get("typosquatting_issues", []):
        similarity = item.get("similarity", 0)
        imitated = item.get("imitated_package")

        aggregator.add_finding(
            Finding(
                id=f"TYPO-{item['component']}",
                type=FindingType.MALWARE,  # Typosquatting is a form of malware/attack
                severity=Severity.CRITICAL,
                component=item.get("component"),
                version=item.get("version"),
                description=f"Possible typosquatting detected! '{item.get('component')}' is {similarity*100:.1f}% similar to popular package '{imitated}'",
                scanners=["typosquatting"],
                details={"imitated_package": imitated, "similarity": similarity},
            ),
            source=source,
        )

def normalize_maintainer_risk(aggregator: "ResultAggregator", result: Dict[str, Any], source: str = None):
    """Normalize maintainer risk results into findings."""
    for item in result.get("maintainer_issues", []):
        risks = item.get("risks", [])

        # Create a combined description from all risks
        risk_messages = [r.get("message", "") for r in risks]
        description = (
            "; ".join(risk_messages)
            if risk_messages
            else "Maintainer risk detected"
        )

        aggregator.add_finding(
            Finding(
                id=f"MAINT-{item['component']}",
                type=FindingType.QUALITY,  # Supply chain quality issue
                severity=Severity(item.get("severity", "MEDIUM")),
                component=item.get("component"),
                version=item.get("version"),
                description=description,
                scanners=["maintainer_risk"],
                details={
                    "risks": risks,
                    "maintainer_info": item.get("maintainer_info", {}),
                    "risk_count": len(risks),
                },
            ),
            source=source,
        )
