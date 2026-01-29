from collections import defaultdict
from typing import Any, Dict, List

from app.schemas.recommendation import Priority, Recommendation, RecommendationType
from app.services.recommendation.common import get_attr, ModelOrDict


def process_sast(findings: List[ModelOrDict]) -> List[Recommendation]:
    """Process SAST (Static Application Security Testing) findings."""
    if not findings:
        return []

    # Group by rule/category
    findings_by_category = defaultdict(list)
    for f in findings:
        details = get_attr(f, "details", {})
        category = (
            (details.get("category") if isinstance(details, dict) else None)
            or (details.get("rule_id") if isinstance(details, dict) else None)
            or (details.get("check_id") if isinstance(details, dict) else None)
            or "security"
        )
        # Normalize category
        category_lower = category.lower()
        if "inject" in category_lower or "sqli" in category_lower:
            category = "Injection"
        elif "xss" in category_lower or "cross-site" in category_lower:
            category = "XSS"
        elif "auth" in category_lower:
            category = "Authentication"
        elif "crypto" in category_lower or "cipher" in category_lower:
            category = "Cryptography"
        elif "path" in category_lower or "traversal" in category_lower:
            category = "Path Traversal"

        findings_by_category[category].append(f)

    recommendations = []

    # Create recommendations per category if significant
    for category, cat_findings in findings_by_category.items():
        severity_counts: Dict[str, int] = defaultdict(int)
        files_affected = set()

        for f in cat_findings:
            severity_counts[get_attr(f, "severity", "UNKNOWN")] += 1
            files_affected.add(get_attr(f, "component", "unknown"))

        critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get(
            "HIGH", 0
        )

        # Only create recommendations for significant issues
        if critical_high < 1 and len(cat_findings) < 3:
            continue

        if severity_counts.get("CRITICAL", 0) > 0:
            priority = Priority.CRITICAL
        elif severity_counts.get("HIGH", 0) > 0:
            priority = Priority.HIGH
        elif severity_counts.get("MEDIUM", 0) > 0:
            priority = Priority.MEDIUM
        else:
            priority = Priority.LOW

        # Extract rule IDs safely
        rule_ids = set()
        for f in cat_findings:
            details = get_attr(f, "details", {})
            if isinstance(details, dict):
                rule_id = details.get("rule_id")
                if rule_id:
                    rule_ids.add(rule_id)

        recommendations.append(
            Recommendation(
                type=RecommendationType.FIX_CODE_SECURITY,
                priority=priority,
                title=f"Fix {category} Issues",
                description=(
                    f"Found {len(cat_findings)} {category} security issues in {len(files_affected)} files. "
                    f"Includes {severity_counts.get('CRITICAL', 0)} critical and "
                    f"{severity_counts.get('HIGH', 0)} high severity issues."
                ),
                impact={
                    "critical": severity_counts.get("CRITICAL", 0),
                    "high": severity_counts.get("HIGH", 0),
                    "medium": severity_counts.get("MEDIUM", 0),
                    "low": severity_counts.get("LOW", 0),
                    "total": len(cat_findings),
                },
                affected_components=list(files_affected)[:20],
                action={
                    "type": "fix_code",
                    "category": category,
                    "files": list(files_affected)[:10],
                    "rules": list(rule_ids)[:10],
                },
                effort="medium" if len(cat_findings) < 10 else "high",
            )
        )

    return recommendations
