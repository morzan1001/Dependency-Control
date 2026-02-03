from collections import defaultdict
from typing import Dict, List

from app.schemas.recommendation import Priority, Recommendation, RecommendationType
from app.services.recommendation.common import get_attr, ModelOrDict


def process_iac(findings: List[ModelOrDict]) -> List[Recommendation]:
    """Process IAC (Infrastructure as Code) findings."""
    if not findings:
        return []

    # Group by platform/category
    findings_by_platform = defaultdict(list)
    for f in findings:
        details = get_attr(f, "details", {})
        query_name = details.get("query_name", "") if isinstance(details, dict) else ""
        platform = (
            (details.get("platform") if isinstance(details, dict) else None)
            or (query_name.split(".")[0] if query_name else None)
            or "infrastructure"
        )
        # Normalize platform
        platform_lower = platform.lower()
        if "docker" in platform_lower:
            platform = "Docker"
        elif "kubernetes" in platform_lower or "k8s" in platform_lower:
            platform = "Kubernetes"
        elif "terraform" in platform_lower:
            platform = "Terraform"
        elif "cloudformation" in platform_lower or "aws" in platform_lower:
            platform = "AWS/CloudFormation"
        elif "ansible" in platform_lower:
            platform = "Ansible"
        elif "helm" in platform_lower:
            platform = "Helm"

        findings_by_platform[platform].append(f)

    recommendations = []

    for platform, plat_findings in findings_by_platform.items():
        severity_counts: Dict[str, int] = defaultdict(int)
        files_affected = set()

        for f in plat_findings:
            severity_counts[get_attr(f, "severity", "UNKNOWN")] += 1
            files_affected.add(get_attr(f, "component", "unknown"))

        critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get(
            "HIGH", 0
        )

        if critical_high < 1 and len(plat_findings) < 3:
            continue

        if severity_counts.get("CRITICAL", 0) > 0:
            priority = Priority.CRITICAL
        elif severity_counts.get("HIGH", 0) > 0:
            priority = Priority.HIGH
        elif severity_counts.get("MEDIUM", 0) > 0:
            priority = Priority.MEDIUM
        else:
            priority = Priority.LOW

        recommendations.append(
            Recommendation(
                type=RecommendationType.FIX_INFRASTRUCTURE,
                priority=priority,
                title=f"Fix {platform} Misconfigurations",
                description=(
                    f"Found {len(plat_findings)} infrastructure security issues in {platform} configurations. "
                    f"Includes {severity_counts.get('CRITICAL', 0)} critical and "
                    f"{severity_counts.get('HIGH', 0)} high severity misconfigurations."
                ),
                impact={
                    "critical": severity_counts.get("CRITICAL", 0),
                    "high": severity_counts.get("HIGH", 0),
                    "medium": severity_counts.get("MEDIUM", 0),
                    "low": severity_counts.get("LOW", 0),
                    "total": len(plat_findings),
                },
                affected_components=list(files_affected)[:20],
                action={
                    "type": "fix_infrastructure",
                    "platform": platform,
                    "files": list(files_affected)[:10],
                    "common_issues": _get_common_iac_issues(plat_findings),
                },
                effort="medium",
            )
        )

    return recommendations


def _get_common_iac_issues(findings: List[ModelOrDict]) -> List[str]:
    """Extract common IAC issue types."""
    issues: Dict[str, int] = defaultdict(int)
    for f in findings:
        details = get_attr(f, "details", {})
        issue_type = (
            (details.get("query_name") if isinstance(details, dict) else None)
            or (details.get("check_id") if isinstance(details, dict) else None)
            or get_attr(f, "description", "")[:50]
        )
        issues[issue_type] += 1

    # Sort by frequency and return top 5
    sorted_issues = sorted(issues.items(), key=lambda x: x[1], reverse=True)
    return [issue for issue, count in sorted_issues[:5]]
