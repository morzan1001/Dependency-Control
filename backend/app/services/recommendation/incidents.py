from typing import List

from app.core.constants import EPSS_VERY_HIGH_THRESHOLD
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.recommendation.common import extract_cve_id, get_attr, ModelOrDict


def process_malware(malware_findings: List[ModelOrDict]) -> List[Recommendation]:
    """Process malware detection findings."""
    if not malware_findings:
        return []

    affected_packages = list({get_attr(f, "component", "") for f in malware_findings})

    return [
        Recommendation(
            type=RecommendationType.MALWARE_DETECTED,
            priority=Priority.CRITICAL,
            title="CRITICAL: Malware Detected in Dependencies",
            description=(
                f"Found {len(malware_findings)} packages containing known malware. "
                f"These packages may steal credentials, install backdoors, or cause other harm. "
                f"Remove immediately!"
            ),
            impact={
                "critical": len(malware_findings),
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": len(malware_findings),
            },
            affected_components=affected_packages,
            action={
                "type": "remove_malware",
                "packages": affected_packages,
                "urgency": "immediate",
                "steps": [
                    "STOP - This is a critical security incident",
                    "1. Immediately remove the malicious package(s)",
                    "2. Check if npm install/pip install scripts ran malicious code",
                    "3. Rotate any credentials that may have been exposed",
                    "4. Audit your systems for signs of compromise",
                    "5. Report to your security team",
                    "6. Consider incident response procedures",
                ],
            },
            effort="low",
        )
    ]


def process_typosquatting(
    typosquat_findings: List[ModelOrDict],
) -> List[Recommendation]:
    """Process potential typosquatting package findings."""
    if not typosquat_findings:
        return []

    affected_packages = []
    for f in typosquat_findings:
        pkg = get_attr(f, "component", "")
        details = get_attr(f, "details", {})
        similar_to = details.get("similar_to", "") if isinstance(details, dict) else ""
        if pkg and similar_to:
            affected_packages.append(f"{pkg} (looks like: {similar_to})")
        elif pkg:
            affected_packages.append(pkg)

    return [
        Recommendation(
            type=RecommendationType.TYPOSQUAT_DETECTED,
            priority=Priority.HIGH,
            title="Potential Typosquatting Packages Detected",
            description=(
                f"Found {len(typosquat_findings)} packages that may be typosquatting attempts. "
                f"Typosquatting packages mimic popular packages to trick developers into installing malware. "
                f"Verify these are the intended packages."
            ),
            impact={
                "critical": 0,
                "high": len(typosquat_findings),
                "medium": 0,
                "low": 0,
                "total": len(typosquat_findings),
            },
            affected_components=affected_packages,
            action={
                "type": "verify_packages",
                "packages": affected_packages,
                "steps": [
                    "1. Verify each flagged package is the intended package",
                    "2. Check the package source repository",
                    "3. Compare with the legitimate package name",
                    "4. If typosquat, replace with the correct package",
                    "5. Audit for any malicious activity",
                ],
            },
            effort="low",
        )
    ]


def detect_known_exploits(vuln_findings: List[ModelOrDict]) -> List[Recommendation]:
    """
    Detect vulnerabilities with known exploits (KEV, ransomware, high EPSS).
    These require immediate action.
    """
    recommendations = []

    kev_vulns = []
    ransomware_vulns = []
    high_epss_vulns = []

    for f in vuln_findings:
        details = get_attr(f, "details", {})
        if isinstance(details, dict) and details.get("is_kev"):
            if details.get("kev_ransomware"):
                ransomware_vulns.append(f)
            else:
                kev_vulns.append(f)
        elif (
            isinstance(details, dict)
            and details.get("epss_score")
            and details.get("epss_score") >= EPSS_VERY_HIGH_THRESHOLD
        ):
            high_epss_vulns.append(f)

    if ransomware_vulns:
        affected_packages = list({get_attr(f, "component", "") for f in ransomware_vulns})
        cves = list({cve for f in ransomware_vulns if (cve := extract_cve_id(f))})

        recommendations.append(
            Recommendation(
                type=RecommendationType.RANSOMWARE_RISK,
                priority=Priority.CRITICAL,
                title="URGENT: Ransomware Campaign Vulnerabilities",
                description=(
                    f"Found {len(ransomware_vulns)} vulnerabilities known to be used in ransomware campaigns. "
                    f"These CVEs are actively targeted by ransomware groups and require immediate remediation. "
                    f"Affected: {', '.join(cves[:5])}"
                ),
                impact={
                    "critical": len(ransomware_vulns),
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "total": len(ransomware_vulns),
                    "kev_ransomware_count": len(ransomware_vulns),
                },
                affected_components=affected_packages[:20],
                action={
                    "type": "fix_ransomware_vulns",
                    "cves": cves,
                    "packages": affected_packages,
                    "urgency": "immediate",
                    "steps": [
                        "This is a CRITICAL security issue - act within hours, not days",
                        "1. Identify all systems running affected packages",
                        "2. Apply patches or updates immediately",
                        "3. If patches unavailable, take affected systems offline",
                        "4. Implement network segmentation to limit blast radius",
                        "5. Enable enhanced logging and monitoring",
                        "6. Brief your security team and management",
                    ],
                },
                effort="low",
            )
        )

    if kev_vulns:
        affected_packages = list({get_attr(f, "component", "") for f in kev_vulns})
        cves = list({cve for f in kev_vulns if (cve := extract_cve_id(f))})

        recommendations.append(
            Recommendation(
                type=RecommendationType.KNOWN_EXPLOIT,
                priority=Priority.CRITICAL,
                title="CISA KEV: Actively Exploited Vulnerabilities",
                description=(
                    f"Found {len(kev_vulns)} vulnerabilities in CISA's Known Exploited Vulnerabilities catalog. "
                    f"These are being actively exploited in real-world attacks. "
                    f"Federal agencies are required to patch these within specific timeframes."
                ),
                impact={
                    "critical": len([v for v in kev_vulns if get_attr(v, "severity") == "CRITICAL"]),
                    "high": len([v for v in kev_vulns if get_attr(v, "severity") == "HIGH"]),
                    "medium": len([v for v in kev_vulns if get_attr(v, "severity") == "MEDIUM"]),
                    "low": 0,
                    "total": len(kev_vulns),
                    "kev_count": len(kev_vulns),
                },
                affected_components=affected_packages[:20],
                action={
                    "type": "fix_kev_vulns",
                    "cves": cves,
                    "packages": affected_packages,
                    "steps": [
                        "1. Prioritize patching these vulnerabilities above all others",
                        "2. Check CISA KEV catalog for remediation deadlines",
                        "3. Update affected packages to fixed versions",
                        "4. If no fix available, implement compensating controls",
                        "5. Document remediation efforts for compliance",
                    ],
                },
                effort="low",
            )
        )

    if high_epss_vulns:
        affected_packages = list({get_attr(f, "component", "") for f in high_epss_vulns})
        cves = list({cve for f in high_epss_vulns if (cve := extract_cve_id(f))})

        max_epss = max(
            (get_attr(f, "details", {}).get("epss_score", 0) if isinstance(get_attr(f, "details", {}), dict) else 0)
            for f in high_epss_vulns
        )

        recommendations.append(
            Recommendation(
                type=RecommendationType.ACTIVELY_EXPLOITED,
                priority=Priority.CRITICAL,
                title="Very High Exploitation Probability",
                description=(
                    f"Found {len(high_epss_vulns)} vulnerabilities with EPSS score > 50%. "
                    f"These have a very high probability of being exploited in the next 30 days. "
                    f"Highest EPSS: {max_epss * 100:.1f}%"
                ),
                impact={
                    "critical": len([v for v in high_epss_vulns if get_attr(v, "severity") == "CRITICAL"]),
                    "high": len([v for v in high_epss_vulns if get_attr(v, "severity") == "HIGH"]),
                    "medium": len([v for v in high_epss_vulns if get_attr(v, "severity") == "MEDIUM"]),
                    "low": 0,
                    "total": len(high_epss_vulns),
                    "high_epss_count": len(high_epss_vulns),
                    "max_epss": max_epss,
                },
                affected_components=affected_packages[:20],
                action={
                    "type": "fix_high_epss_vulns",
                    "cves": cves,
                    "packages": affected_packages,
                    "max_epss_percent": f"{max_epss * 100:.1f}%",
                    "steps": [
                        "1. These vulnerabilities are likely to be exploited soon",
                        "2. Prioritize remediation before exploit code becomes public",
                        "3. Update affected packages to fixed versions",
                        "4. Monitor threat intelligence for exploit activity",
                    ],
                },
                effort="low",
            )
        )

    return recommendations
