from collections import Counter, defaultdict

from app.schemas.recommendation import Recommendation, RecommendationType
from app.services.recommendation.common import (
    ModelOrDict,
    get_attr,
    label_by_keywords,
    priority_for,
    sample_components,
    severity_impact,
    worth_a_card,
)

_PLATFORM_KEYWORDS = (
    (("docker",), "Docker"),
    (("kubernetes", "k8s"), "Kubernetes"),
    (("terraform",), "Terraform"),
    (("cloudformation", "aws"), "AWS/CloudFormation"),
    (("ansible",), "Ansible"),
    (("helm",), "Helm"),
)


def process_iac(findings: list[ModelOrDict]) -> list[Recommendation]:
    """Process IAC (Infrastructure as Code) findings."""
    findings_by_platform = defaultdict(list)
    for f in findings:
        findings_by_platform[label_by_keywords(get_attr(f, "details")["platform"], _PLATFORM_KEYWORDS)].append(f)

    recommendations = []

    for platform, plat_findings in findings_by_platform.items():
        impact = severity_impact(get_attr(f, "severity", "UNKNOWN") for f in plat_findings)
        if not worth_a_card(impact):
            continue

        files_shown, files_total = sample_components(
            sorted({get_attr(f, "component", "unknown") for f in plat_findings})
        )

        recommendations.append(
            Recommendation(
                type=RecommendationType.FIX_INFRASTRUCTURE,
                priority=priority_for(impact),
                title=f"Fix {platform} Misconfigurations",
                description=(
                    f"Found {len(plat_findings)} infrastructure security issues in {platform} configurations. "
                    f"Includes {impact['critical']} critical and {impact['high']} high severity misconfigurations."
                ),
                impact=impact,
                affected_components=files_shown,
                affected_components_total=files_total,
                action={
                    "type": "fix_infrastructure",
                    "platform": platform,
                    "files": files_shown,
                    "files_total": files_total,
                    "common_issues": _get_common_iac_issues(plat_findings),
                },
                effort="medium",
            )
        )

    return recommendations


def _get_common_iac_issues(findings: list[ModelOrDict]) -> list[str]:
    issues = Counter(get_attr(f, "details")["title"] for f in findings)
    return [issue for issue, _ in issues.most_common(5)]
