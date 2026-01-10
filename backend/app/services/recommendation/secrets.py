from collections import defaultdict
from typing import Any, Dict, List

from app.schemas.recommendation import Priority, Recommendation, RecommendationType

def process_secrets(findings: List[Dict[str, Any]]) -> List[Recommendation]:
    """Process secret/credential findings."""
    if not findings:
        return []

    # Group secrets by type/detector
    secrets_by_type = defaultdict(list)
    for f in findings:
        details = f.get("details", {})
        detector = (
            details.get("detector_type") or details.get("rule_id") or "generic"
        )
        secrets_by_type[detector].append(f)

    recommendations = []

    # Count severities
    severity_counts = defaultdict(int)
    files_affected = set()

    for f in findings:
        severity_counts[f.get("severity", "UNKNOWN")] += 1
        component = f.get("component", "")
        if component:
            files_affected.add(component)

    # Determine priority
    if severity_counts.get("CRITICAL", 0) > 0 or severity_counts.get("HIGH", 0) > 0:
        priority = Priority.CRITICAL  # Secrets are always critical
    else:
        priority = Priority.HIGH

    # Create main recommendation
    secret_types = list(secrets_by_type.keys())[:5]

    recommendations.append(
        Recommendation(
            type=RecommendationType.ROTATE_SECRETS,
            priority=priority,
            title="Rotate Exposed Credentials",
            description=(
                f"Found {len(findings)} exposed secrets/credentials in {len(files_affected)} files. "
                f"These include: {', '.join(secret_types)}. "
                f"Immediately rotate all affected credentials and remove from code."
            ),
            impact={
                "critical": severity_counts.get("CRITICAL", 0),
                "high": severity_counts.get("HIGH", 0),
                "medium": severity_counts.get("MEDIUM", 0),
                "low": severity_counts.get("LOW", 0),
                "total": len(findings),
            },
            affected_components=list(files_affected)[:20],
            action={
                "type": "rotate_secrets",
                "secret_types": secret_types,
                "files": list(files_affected)[:10],
                "steps": [
                    "1. Immediately rotate/regenerate all exposed credentials",
                    "2. Update applications using these credentials",
                    "3. Remove secrets from code and use environment variables or secret managers",
                    "4. Add secret patterns to .gitignore and pre-commit hooks",
                    "5. Scan git history for previously committed secrets",
                ],
            },
            effort="high",
        )
    )

    return recommendations
