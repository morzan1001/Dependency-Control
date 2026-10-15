from collections import Counter, defaultdict

from app.schemas.recommendation import Effort, Recommendation, RecommendationType
from app.services.recommendation.common import (
    AFFECTED_COMPONENTS_SHOWN,
    ModelOrDict,
    get_attr,
    label_by_keywords,
    priority_for,
    recommend,
    sampled,
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
    findings_by_platform = defaultdict(list)
    for f in findings:
        findings_by_platform[label_by_keywords(get_attr(f, "details")["platform"], _PLATFORM_KEYWORDS)].append(f)

    recommendations = []

    for platform, plat_findings in findings_by_platform.items():
        impact = severity_impact(get_attr(f, "severity", "UNKNOWN") for f in plat_findings)
        if not worth_a_card(impact):
            continue

        files = sorted({get_attr(f, "component", "unknown") for f in plat_findings})

        recommendations.append(
            recommend(
                rec_type=RecommendationType.FIX_INFRASTRUCTURE,
                priority=priority_for(impact),
                title=f"Fix {platform} Misconfigurations",
                description=(
                    f"Found {len(plat_findings)} infrastructure security issues in {platform} configurations. "
                    f"Includes {impact['critical']} critical and {impact['high']} high severity misconfigurations."
                ),
                impact=impact,
                components=files,
                action={
                    "type": "fix_infrastructure",
                    "platform": platform,
                    **sampled("files", files, AFFECTED_COMPONENTS_SHOWN),
                    "common_issues": _get_common_iac_issues(plat_findings),
                },
                effort=Effort.MEDIUM,
            )
        )

    return recommendations


def _get_common_iac_issues(findings: list[ModelOrDict]) -> list[str]:
    issues = Counter(get_attr(f, "details")["title"] for f in findings)
    return [issue for issue, _ in issues.most_common(5)]
