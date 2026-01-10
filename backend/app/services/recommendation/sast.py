from collections import defaultdict
from typing import Any, Dict, List

from app.schemas.recommendation import Priority, Recommendation, RecommendationType


def process_sast(findings: List[Dict[str, Any]]) -> List[Recommendation]:
    """Process SAST (Static Application Security Testing) findings."""
    if not findings:
        return []

    # Group by rule/category
    findings_by_category = defaultdict(list)
    for f in findings:
        details = f.get("details", {})
        category = (
            details.get("category")
            or details.get("rule_id")
            or details.get("check_id")
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
            severity_counts[f.get("severity", "UNKNOWN")] += 1
            files_affected.add(f.get("component", "unknown"))

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
                    "rules": list(
                        set(
                            f.get("details", {}).get("rule_id", "")
                            for f in cat_findings
                            if f.get("details", {}).get("rule_id")
                        )
                    )[:10],
                },
                effort="medium" if len(cat_findings) < 10 else "high",
            )
        )

    return recommendations
