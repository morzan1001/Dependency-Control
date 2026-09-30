from collections import defaultdict
from typing import Any

from app.schemas.recommendation import Effort, Recommendation, RecommendationType
from app.services.analytics.findings_delta import sast_rule_ids
from app.services.recommendation.common import (
    ModelOrDict,
    get_attr,
    label_by_keywords,
    priority_for,
    sample_components,
    sampled,
    severity_impact,
    worth_a_card,
)

# Rules named per category card; `sampled` pairs the sample with its population.
_RULES_SAMPLED = 10

_CWE_CATEGORIES = {
    **dict.fromkeys(("77", "78", "89", "90", "94", "917"), "Injection"),
    **dict.fromkeys(("79", "80"), "XSS"),
    **dict.fromkeys(("287", "306", "798", "522"), "Authentication"),
    **dict.fromkeys(("326", "327", "328", "916"), "Cryptography"),
    **dict.fromkeys(("22", "23", "35"), "Path Traversal"),
}
_CATEGORY_KEYWORDS = (
    (("inject", "sqli"), "Injection"),
    (("xss", "cross-site"), "XSS"),
    (("auth",), "Authentication"),
    (("crypto", "cipher"), "Cryptography"),
    (("path", "traversal"), "Path Traversal"),
)


def _finding_category(details: dict[str, Any]) -> str:
    """CWE first; OpenGrep registry rules all set category 'security', so it names a card only when more specific."""
    entries = details.get("sast_findings") or []
    scanner_details = [entry.get("details") or {} for entry in entries]
    by_cwe = [_CWE_CATEGORIES[cwe] for d in scanner_details for cwe in d.get("cwe_ids") or [] if cwe in _CWE_CATEGORIES]
    if by_cwe:
        return by_cwe[0]
    labels = [
        *(d["vulnerability_class"][0] for d in scanner_details if d.get("vulnerability_class")),
        *(d["category"] for d in scanner_details if d.get("category") not in (None, "", "security")),
        *(
            d["title"]
            for e, d in zip(entries, scanner_details, strict=True)
            if e.get("scanner") == "bearer" and d.get("title")
        ),
        *sast_rule_ids(details),
    ]
    return label_by_keywords(labels[0], _CATEGORY_KEYWORDS) if labels else "security"


def process_sast(findings: list[ModelOrDict]) -> list[Recommendation]:
    """Process SAST (Static Application Security Testing) findings."""
    findings_by_category = defaultdict(list)
    for f in findings:
        findings_by_category[_finding_category(get_attr(f, "details", {}))].append(f)

    recommendations = []

    for category, cat_findings in findings_by_category.items():
        impact = severity_impact(get_attr(f, "severity", "UNKNOWN") for f in cat_findings)
        if not worth_a_card(impact):
            continue

        files = sorted({get_attr(f, "component", "unknown") for f in cat_findings})
        files_shown, files_total = sample_components(files)
        rule_ids = sorted(set().union(*(sast_rule_ids(get_attr(f, "details", {})) for f in cat_findings)))

        recommendations.append(
            Recommendation(
                type=RecommendationType.FIX_CODE_SECURITY,
                priority=priority_for(impact),
                title=f"Fix {category} Issues",
                description=(
                    f"Found {len(cat_findings)} {category} security issues in {len(files)} files. "
                    f"Includes {impact['critical']} critical and {impact['high']} high severity issues."
                ),
                impact=impact,
                affected_components=files_shown,
                affected_components_total=files_total,
                action={
                    "type": "fix_code",
                    "category": category,
                    "files": files_shown,
                    "files_total": files_total,
                    **sampled("rules", rule_ids, _RULES_SAMPLED),
                },
                effort=Effort.MEDIUM if len(cat_findings) < 10 else Effort.HIGH,
            )
        )

    return recommendations
