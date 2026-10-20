from collections.abc import Mapping

from app.core.constants import EPSS_VERY_HIGH_THRESHOLD
from app.schemas.enrichment import VulnerabilityEnrichment
from app.schemas.recommendation import (
    Effort,
    Priority,
    Recommendation,
    RecommendationType,
)
from app.services.recommendation.common import (
    AFFECTED_COMPONENTS_SHOWN,
    MALWARE_REMEDIATION_STEPS,
    ModelOrDict,
    cve_severities,
    cve_signals,
    get_attr,
    live_advisories,
    name_some,
    recommend,
    sampled,
    severity_impact,
)

_CVES_NAMED = 5


def _exploited_cves(
    finding: ModelOrDict, threat_intel: Mapping[str, VulnerabilityEnrichment]
) -> tuple[set[str], set[str], dict[str, float]]:
    """Confirmed exploitation (ransomware, then KEV) outranks prediction (high EPSS)."""
    ransomware: set[str] = set()
    kev: set[str] = set()
    epss: dict[str, float] = {}
    for cve, in_kev, ransomware_use, epss_score in cve_signals(
        live_advisories(get_attr(finding, "details", {})), threat_intel
    ):
        if ransomware_use:
            ransomware.add(cve)
        elif in_kev:
            kev.add(cve)
        elif epss_score >= EPSS_VERY_HIGH_THRESHOLD:
            epss[cve] = max(epss_score, epss.get(cve, 0.0))
    return ransomware, kev, epss


def _packages(findings: list[ModelOrDict]) -> list[str]:
    return sorted({get_attr(f, "component", "") for f in findings})


def process_malware(malware_findings: list[ModelOrDict]) -> list[Recommendation]:
    if not malware_findings:
        return []

    packages = _packages(malware_findings)

    return [
        recommend(
            rec_type=RecommendationType.MALWARE_DETECTED,
            priority=Priority.CRITICAL,
            title="CRITICAL: Malware Detected in Dependencies",
            description=(
                f"Found {len(packages)} packages containing known malware. "
                f"These packages may steal credentials, install backdoors, or cause other harm. "
                f"Remove immediately!"
            ),
            impact=severity_impact("CRITICAL" for _ in packages),
            components=packages,
            action={
                "type": "remove_malware",
                **sampled("packages", packages, AFFECTED_COMPONENTS_SHOWN),
                "urgency": "immediate",
                "steps": list(MALWARE_REMEDIATION_STEPS),
            },
            effort=Effort.LOW,
        )
    ]


def process_hash_mismatch(findings: list[ModelOrDict]) -> list[Recommendation]:
    """Mirrors, tarball and git sources fail the registry hash check too, so the card asks to verify first."""
    if not findings:
        return []

    packages = _packages(findings)

    return [
        recommend(
            rec_type=RecommendationType.HASH_MISMATCH,
            priority=Priority.HIGH,
            title="Package Integrity Check Failed",
            description=(
                f"{len(packages)} packages do not match the hashes their registry publishes. "
                "The artifact may have been tampered with, or it came from a mirror, tarball or git source."
            ),
            impact=severity_impact("HIGH" for _ in packages),
            components=packages,
            action={
                "type": "verify_integrity",
                **sampled("packages", packages, AFFECTED_COMPONENTS_SHOWN),
                "steps": [
                    "Compare the lockfile integrity hash with the hash the registry publishes",
                    "Check whether the package came from a private registry, mirror, tarball or git source",
                    "Re-fetch the package from the canonical registry and scan again",
                    "Escalate as tampering only if the mismatch persists",
                ],
            },
            effort=Effort.LOW,
        )
    ]


def process_typosquatting(typosquat_findings: list[ModelOrDict]) -> list[Recommendation]:
    if not typosquat_findings:
        return []

    affected_packages = sorted(
        {
            f"{get_attr(f, 'component')} (looks like: {get_attr(f, 'details')['imitated_package']})"
            for f in typosquat_findings
        }
    )
    return [
        recommend(
            rec_type=RecommendationType.TYPOSQUAT_DETECTED,
            priority=Priority.HIGH,
            title="Potential Typosquatting Packages Detected",
            description=(
                f"Found {len(affected_packages)} packages that may be typosquatting attempts. "
                f"Typosquatting packages mimic popular packages to trick developers into installing malware. "
                f"Verify these are the intended packages."
            ),
            impact=severity_impact("HIGH" for _ in affected_packages),
            components=affected_packages,
            action={
                "type": "verify_packages",
                **sampled("packages", affected_packages, AFFECTED_COMPONENTS_SHOWN),
                "steps": [
                    "Verify each flagged package is the intended package",
                    "Check the package source repository",
                    "Compare with the legitimate package name",
                    "If typosquat, replace with the correct package",
                    "Audit for any malicious activity",
                ],
            },
            effort=Effort.LOW,
        )
    ]


def detect_known_exploits(
    vuln_findings: list[ModelOrDict], threat_intel: Mapping[str, VulnerabilityEnrichment] | None = None
) -> list[Recommendation]:
    recommendations = []

    kev_vulns: list[ModelOrDict] = []
    ransomware_vulns: list[ModelOrDict] = []
    high_epss_vulns: list[ModelOrDict] = []
    kev_cves: set[str] = set()
    ransomware_cves: set[str] = set()
    high_epss_cves: set[str] = set()
    max_epss = 0.0

    for f in vuln_findings:
        ransomware, kev, epss = _exploited_cves(f, threat_intel or {})
        if ransomware:
            ransomware_vulns.append(f)
            ransomware_cves |= ransomware
        if kev:
            kev_vulns.append(f)
            kev_cves |= kev
        if epss:
            high_epss_vulns.append(f)
            high_epss_cves |= epss.keys()
            max_epss = max(max_epss, *epss.values())
    severity = cve_severities(a for f in vuln_findings for a in live_advisories(get_attr(f, "details", {})))

    if ransomware_vulns:
        packages = _packages(ransomware_vulns)
        cves = sorted(ransomware_cves)

        recommendations.append(
            recommend(
                rec_type=RecommendationType.RANSOMWARE_RISK,
                priority=Priority.CRITICAL,
                title="URGENT: Ransomware Campaign Vulnerabilities",
                description=(
                    f"Found {len(ransomware_cves)} vulnerabilities known to be used in ransomware campaigns. "
                    f"These CVEs are actively targeted by ransomware groups and require immediate remediation. "
                    f"Affected: {name_some(cves, _CVES_NAMED)}"
                ),
                impact={
                    **severity_impact(severity[cve] for cve in ransomware_cves),
                    "kev_ransomware_count": len(ransomware_cves),
                },
                components=packages,
                action={
                    "type": "fix_ransomware_vulns",
                    **sampled("cves", cves, AFFECTED_COMPONENTS_SHOWN),
                    **sampled("packages", packages, AFFECTED_COMPONENTS_SHOWN),
                    "urgency": "immediate",
                    "steps": [
                        "Identify all systems running affected packages",
                        "Apply patches or updates immediately",
                        "If patches unavailable, take affected systems offline",
                        "Implement network segmentation to limit blast radius",
                        "Enable enhanced logging and monitoring",
                        "Brief your security team and management",
                    ],
                },
                effort=Effort.LOW,
            )
        )

    if kev_vulns:
        packages = _packages(kev_vulns)

        recommendations.append(
            recommend(
                rec_type=RecommendationType.KNOWN_EXPLOIT,
                priority=Priority.CRITICAL,
                title="CISA KEV: Actively Exploited Vulnerabilities",
                description=(
                    f"Found {len(kev_cves)} vulnerabilities in CISA's Known Exploited Vulnerabilities catalog. "
                    f"These are being actively exploited in real-world attacks. "
                    f"Federal agencies are required to patch these within specific timeframes."
                ),
                impact={**severity_impact(severity[cve] for cve in kev_cves), "kev_count": len(kev_cves)},
                components=packages,
                action={
                    "type": "fix_kev_vulns",
                    **sampled("cves", sorted(kev_cves), AFFECTED_COMPONENTS_SHOWN),
                    **sampled("packages", packages, AFFECTED_COMPONENTS_SHOWN),
                    "steps": [
                        "Prioritize patching these vulnerabilities above all others",
                        "Check CISA KEV catalog for remediation deadlines",
                        "Update affected packages to fixed versions",
                        "If no fix available, implement compensating controls",
                        "Document remediation efforts for compliance",
                    ],
                },
                effort=Effort.LOW,
            )
        )

    if high_epss_vulns:
        packages = _packages(high_epss_vulns)

        recommendations.append(
            recommend(
                rec_type=RecommendationType.ACTIVELY_EXPLOITED,
                priority=Priority.CRITICAL,
                title="Very High Exploitation Probability",
                description=(
                    f"Found {len(high_epss_cves)} vulnerabilities with EPSS score >= {EPSS_VERY_HIGH_THRESHOLD:.0%}. "
                    f"These have a very high probability of being exploited in the next 30 days. "
                    f"Highest EPSS: {max_epss * 100:.1f}%"
                ),
                impact={
                    **severity_impact(severity[cve] for cve in high_epss_cves),
                    "high_epss_count": len(high_epss_cves),
                    "max_epss": max_epss,
                },
                components=packages,
                action={
                    "type": "fix_high_epss_vulns",
                    **sampled("cves", sorted(high_epss_cves), AFFECTED_COMPONENTS_SHOWN),
                    **sampled("packages", packages, AFFECTED_COMPONENTS_SHOWN),
                    "max_epss_percent": f"{max_epss * 100:.1f}%",
                    "steps": [
                        "Prioritize remediation before exploit code becomes public",
                        "Update affected packages to fixed versions",
                        "Monitor threat intelligence for exploit activity",
                    ],
                },
                effort=Effort.LOW,
            )
        )

    return recommendations
