from collections import defaultdict
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any

from app.core.constants import SCORECARD_POOR_QUALITY_THRESHOLD, SEVERITY_CALCULATED_RISK_SCORES
from app.models.finding import PACKAGE_FINDING_TYPES
from app.schemas.recommendation import (
    Priority,
    Recommendation,
    RecommendationType,
    VulnerabilityInfo,
)
from app.services.aggregation.versions import newest_first, normalize_version
from app.services.component_identity import (
    build_component_index,
    cluster_by_package_identity,
    lookup_component,
    normalize_component,
)
from app.services.recommendation.graph import build_dependency_edges
from app.services.recommendation.common import (
    AFFECTED_COMPONENTS_SHOWN,
    MALWARE_REMEDIATION_STEPS,
    ModelOrDict,
    VulnStats,
    dependency_label,
    live_cves,
    get_attr,
    malware_kind,
    name_some,
    sample_components,
    scorecard_score,
    summarize_vulns,
    take_top,
    vuln_info,
    vuln_priority,
)

# Hotspots and toxic packages are one recommendation each, so these bound the advice feed
# rather than a list inside one card; each emitted card carries the rank it was cut at.
CRITICAL_HOTSPOTS_SHOWN = 10
TOXIC_DEPENDENCIES_SHOWN = 5
# Parents named per transitive dependency on the attack-surface card before "and N more".
_PARENTS_NAMED = 3

# Scorecard and license findings land on every installed copy; these single one out.
_COPY_FINDING_TYPES = frozenset({"vulnerability", "malware", "eol"})


@dataclass
class _PackageRisks:
    """Every fact the hotspot and toxic cards read about one package, from one pass over its findings."""

    name: str
    finding_versions: set[str] = field(default_factory=set)
    flagged_versions: set[str] = field(default_factory=set)
    vulns: list[VulnerabilityInfo] = field(default_factory=list)
    has_malware: bool = False
    is_eol: bool = False
    low_scorecard: float | None = None
    # (severity, license) of the first CRITICAL or HIGH license finding.
    license_issue: tuple[str, str] | None = None

    @cached_property
    def stats(self) -> VulnStats:
        return summarize_vulns(self.vulns)

    @cached_property
    def risk_score(self) -> float:
        # Unenriched advisories (GHSA-only, GO-, RUSTSEC-) fall back on the same 0..100 scale.
        return sum(
            v.risk_score or SEVERITY_CALCULATED_RISK_SCORES.get((v.severity or "").upper(), 0.0) for v in self.vulns
        )

    @property
    def versions(self) -> list[str]:
        return newest_first(self.flagged_versions or self.finding_versions)

    @property
    def labels(self) -> list[str]:
        return [f"{self.name}@{version}" for version in self.versions or ["unknown"]]


def _record(pkg: _PackageRisks, finding: ModelOrDict) -> None:
    finding_type = get_attr(finding, "type")
    details = get_attr(finding, "details", {})
    details = details if isinstance(details, dict) else {}
    if finding_type == "vulnerability":
        # The vulnerability carries the most qualified spelling of the package.
        if not pkg.vulns:
            pkg.name = get_attr(finding, "component")
        pkg.vulns.append(vuln_info(finding))
    elif finding_type == "malware" and malware_kind(finding) == "malware":
        pkg.has_malware = True
    elif finding_type == "eol":
        pkg.is_eol = True
    elif finding_type == "quality":
        score = scorecard_score(details)
        if pkg.low_scorecard is None and score is not None and score < SCORECARD_POOR_QUALITY_THRESHOLD:
            pkg.low_scorecard = score
    elif finding_type == "license":
        severity = get_attr(finding, "severity")
        if pkg.license_issue is None and severity in ("CRITICAL", "HIGH"):
            pkg.license_issue = (severity, details.get("license", "unknown"))


def roll_up_packages(findings: list[ModelOrDict]) -> list[_PackageRisks]:
    package_findings = [
        f for f in findings if get_attr(f, "component") and get_attr(f, "type") in PACKAGE_FINDING_TYPES
    ]
    # Scorecard, license and EOL findings carry the SBOM name, a Maven vulnerability group:artifact.
    representative = cluster_by_package_identity(get_attr(f, "component") for f in package_findings)
    packages: dict[str, _PackageRisks] = {}
    for f in package_findings:
        component = get_attr(f, "component")
        pkg = packages.setdefault(representative[normalize_component(component)], _PackageRisks(name=component))
        if version := get_attr(f, "version"):
            pkg.finding_versions.add(version)
            if get_attr(f, "type") in _COPY_FINDING_TYPES:
                pkg.flagged_versions.add(version)
        _record(pkg, f)
    return list(packages.values())


def detect_critical_hotspots(packages: list[_PackageRisks]) -> list[Recommendation]:
    hotspots = [(pkg, reasons) for pkg in packages for is_hotspot, reasons in [_hotspot_reasons(pkg)] if is_hotspot]
    hotspots.sort(key=lambda h: (h[0].has_malware, h[0].stats.kev, h[0].stats.high_epss, h[0].risk_score), reverse=True)
    return [
        _hotspot_recommendation(pkg, reasons, rank, population)
        for rank, (pkg, reasons), population in take_top(hotspots, CRITICAL_HOTSPOTS_SHOWN)
    ]


def detect_toxic_dependencies(packages: list[_PackageRisks]) -> list[Recommendation]:
    # The malware and hotspot cards already tell the user to remove a malware package.
    toxic = [
        (pkg, factors, score)
        for pkg in packages
        if not pkg.has_malware
        for factors, score in [_toxic_risk_factors(pkg)]
        if len(factors) >= 2
    ]
    toxic.sort(key=lambda t: t[2], reverse=True)
    return [
        _toxic_recommendation(pkg, factors, score, rank, population)
        for rank, (pkg, factors, score), population in take_top(toxic, TOXIC_DEPENDENCIES_SHOWN)
    ]


def _hotspot_reasons(pkg: _PackageRisks) -> tuple[bool, list[str]]:
    """Whether a package is a hotspot, and every reason the card names."""
    stats = pkg.stats
    is_hotspot = False
    reasons: list[str] = []

    if pkg.has_malware:
        is_hotspot = True
        reasons.append("Malware detected")
    if stats.kev > 0:
        is_hotspot = True
        reasons.append(f"{stats.kev} CVE(s) in CISA KEV")
    if stats.high_epss > 0 and stats.reachable > 0:
        is_hotspot = True
        reasons.append(f"{stats.high_epss} high-EPSS CVE(s), {stats.reachable} reachable")

    critical, high = stats.severity["CRITICAL"], stats.severity["HIGH"]
    if stats.total >= 3 and critical + high >= 1:
        is_hotspot = True
        reasons.append(f"{stats.total} vulnerabilities ({critical} critical, {high} high)")

    if pkg.low_scorecard is not None:
        reasons.append(f"Low OpenSSF Scorecard: {pkg.low_scorecard}/10")
    if pkg.is_eol:
        reasons.append("End-of-Life dependency")

    return is_hotspot, reasons


def _hotspot_steps(pkg: _PackageRisks) -> list[str]:
    """Specific remediation steps for a hotspot."""
    if pkg.has_malware:
        return list(MALWARE_REMEDIATION_STEPS)
    if pkg.stats.kev > 0:
        return [
            "Update to a fixed version immediately if available",
            "If no fix exists, implement compensating controls",
            "Monitor for signs of exploitation in your environment",
            "Consider WAF rules or network segmentation as temporary mitigation",
        ]
    if pkg.stats.fixed_versions:
        return [
            f"Update {pkg.name} to version {pkg.stats.best_fix} or later",
            "Run tests to ensure compatibility",
            "Deploy the updated dependency",
            "Verify the vulnerabilities are resolved in your next scan",
        ]
    return [
        "Evaluate if this package is essential to your application",
        "Search for alternative packages with better security posture",
        "If no alternatives exist, implement compensating controls",
        "Monitor for security updates from the package maintainer",
        "Consider contributing a fix if the package is open source",
    ]


def _hotspot_recommendation(pkg: _PackageRisks, reasons: list[str], rank: int, ranked_out_of: int) -> Recommendation:
    stats = pkg.stats
    priority = Priority.CRITICAL if pkg.has_malware or vuln_priority(stats) == Priority.CRITICAL else Priority.HIGH
    summary = (
        "is a critical security hotspot that requires immediate attention"
        if priority == Priority.CRITICAL
        else "is a security hotspot that should be addressed soon"
    )
    desc_parts = [f"**{', '.join(pkg.labels)}** {summary}.", *reasons]
    if stats.fixed_versions:
        desc_parts.append(f"Available fix: Update to {stats.best_fix}")
    components_shown, components_total = sample_components(pkg.labels)

    return Recommendation(
        type=RecommendationType.CRITICAL_HOTSPOT,
        priority=priority,
        title=f"Critical Hotspot: {pkg.name}",
        description=" | ".join(desc_parts),
        impact={
            "critical": stats.severity["CRITICAL"],
            "high": stats.severity["HIGH"],
            "medium": 0,
            "low": 0,
            "total": stats.total,
            "kev_count": stats.kev,
            "high_epss_count": stats.high_epss,
            "reachable_count": stats.reachable,
            "risk_score": pkg.risk_score,
        },
        affected_components=components_shown,
        affected_components_total=components_total,
        action={
            "type": "fix_hotspot",
            "package": pkg.name,
            "current_versions": pkg.versions,
            "fixed_versions": stats.fixed_versions,
            "target_version": stats.best_fix,
            "reasons": reasons,
            "is_malware": pkg.has_malware,
            "is_kev": stats.kev > 0,
            "steps": _hotspot_steps(pkg),
        },
        effort="low" if pkg.has_malware or stats.fixed_versions else "high",
        rank=rank,
        ranked_out_of=ranked_out_of,
    )


def _vuln_risk_severity(critical: int, high: int, kev: int) -> str:
    """Determine severity label for vulnerability risk factor."""
    if critical > 0 or kev > 0:
        return "CRITICAL"
    if high > 0:
        return "HIGH"
    return "MEDIUM"


def _toxic_risk_factors(pkg: _PackageRisks) -> tuple[list[dict[str, str]], int]:
    """A package's independent risk factors and the score ranking toxic packages."""
    factors: list[dict[str, str]] = []
    score = 0
    if pkg.is_eol:
        factors.append({"type": "eol", "severity": "HIGH", "description": "End-of-Life - no security updates"})
        score += 40
    if pkg.low_scorecard is not None:
        factors.append(
            {"type": "low_scorecard", "severity": "HIGH", "description": f"OpenSSF Scorecard: {pkg.low_scorecard}/10"}
        )
        score += 30
    if pkg.license_issue is not None:
        severity, license_name = pkg.license_issue
        factors.append(
            {
                "type": "license_issue",
                "severity": severity,
                "description": f"License compliance issue: {license_name}",
            }
        )
        score += 20

    stats = pkg.stats
    if stats.total:
        critical, high = stats.severity["CRITICAL"], stats.severity["HIGH"]
        factors.append(
            {
                "type": "vulnerabilities",
                "severity": _vuln_risk_severity(critical, high, stats.kev),
                "description": f"{stats.total} vulnerabilities ({critical} critical, {high} high, {stats.kev} KEV)",
            }
        )
        score += critical * 50 + high * 20 + stats.total * 5 + stats.kev * 100
    return factors, score


def _toxic_recommendation(
    pkg: _PackageRisks, factors: list[dict[str, str]], score: int, rank: int, ranked_out_of: int
) -> Recommendation:
    stats = pkg.stats
    components_shown, components_total = sample_components(pkg.labels)
    return Recommendation(
        type=RecommendationType.TOXIC_DEPENDENCY,
        priority=Priority.HIGH,
        title=f"Toxic Dependency: {pkg.name}",
        description=(
            f"This package has multiple independent risk factors: "
            f"{' | '.join(factor['description'] for factor in factors)}. "
            f"Consider replacing it with a safer alternative."
        ),
        impact={
            "critical": stats.severity["CRITICAL"],
            "high": stats.severity["HIGH"],
            "medium": stats.severity["MEDIUM"],
            "low": 0,
            "total": stats.total,
            "risk_factor_count": len(factors),
            "toxic_score": score,
        },
        affected_components=components_shown,
        affected_components_total=components_total,
        action={
            "type": "replace_toxic_dependency",
            "package": pkg.name,
            "versions": pkg.versions,
            "risk_factors": factors,
            "steps": [
                f"Evaluate if {pkg.name} is essential to your application",
                "Search for alternative packages with better security posture",
                "Check npm/pypi/crates.io for actively maintained alternatives",
                "If essential, implement additional security controls",
                "Plan migration to a safer alternative",
            ],
        },
        effort="high",
        rank=rank,
        ranked_out_of=ranked_out_of,
    )


def analyze_attack_surface(
    dependencies: list[ModelOrDict],
    findings: list[ModelOrDict],
) -> list[Recommendation]:
    """Analyze attack surface and recommend reduction strategies."""
    if not dependencies:
        return []

    recommendations = []

    # Advisories per installed copy: another version of the package carries its own.
    counts_by_version: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        if get_attr(f, "type") == "vulnerability":
            counts_by_version[normalize_version(get_attr(f, "version"))][get_attr(f, "component", "")] += (
                len(live_cves([get_attr(f, "details")])) or 1
            )
    # Findings carry the qualified component while the inventory keeps the bare name.
    index_by_version = {version: build_component_index(counts) for version, counts in counts_by_version.items()}
    edges = build_dependency_edges(dependencies)
    by_label: dict[str, dict[str, Any]] = {}
    for key, dep in edges.dep_by_key.items():
        version = get_attr(dep, "version") or ""
        vuln_count = (
            lookup_component(index_by_version.get(normalize_version(version), {}), get_attr(dep, "name", "")) or 0
        )
        if key not in edges.direct_keys and vuln_count >= 2:
            by_label.setdefault(
                dependency_label(dep),
                {
                    "name": get_attr(dep, "name", ""),
                    "version": version,
                    "vuln_count": vuln_count,
                    # A parent ref naming no inventory entry is shown as stored.
                    "parents": [
                        dependency_label(edges.dep_by_key[ref]) if ref in edges.dep_by_key else ref
                        for ref in edges.parents_by_key[key]
                    ],
                },
            )
    transitive_with_vulns = list(by_label.values())

    if transitive_with_vulns:
        transitive_with_vulns.sort(key=lambda x: x["vuln_count"], reverse=True)

        total_vulns = sum(t["vuln_count"] for t in transitive_with_vulns)
        transitive_shown, transitive_total = sample_components(
            f"{t['name']}@{t['version']}"
            + (f" (via {name_some(t['parents'], _PARENTS_NAMED)})" if t["parents"] else "")
            for t in transitive_with_vulns
        )

        recommendations.append(
            Recommendation(
                type=RecommendationType.ATTACK_SURFACE_REDUCTION,
                priority=Priority.MEDIUM,
                title="Reduce Attack Surface via Transitive Dependencies",
                description=(
                    f"Found {len(transitive_with_vulns)} transitive dependencies "
                    f"contributing {total_vulns} vulnerabilities. "
                    "Consider updating or replacing their parent dependencies "
                    "to reduce attack surface."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": total_vulns,
                    "low": 0,
                    "total": total_vulns,
                },
                affected_components=transitive_shown,
                affected_components_total=transitive_total,
                action={
                    "type": "reduce_attack_surface",
                    "transitive_deps": transitive_with_vulns[:AFFECTED_COMPONENTS_SHOWN],
                    "steps": [
                        "Review which parent dependencies introduce vulnerable transitives",
                        "Check if parent dependencies have updates that use fixed versions",
                        "Consider using dependency overrides to force specific versions",
                        "Evaluate if parent dependencies are essential or could be removed",
                    ],
                },
                effort="medium",
            )
        )

    total_deps = len(dependencies)
    direct_deps = len([d for d in dependencies if get_attr(d, "direct", False)])

    if total_deps > 500 and direct_deps < total_deps * 0.1:
        recommendations.append(
            Recommendation(
                type=RecommendationType.ATTACK_SURFACE_REDUCTION,
                priority=Priority.LOW,
                title="Large Dependency Tree",
                description=(
                    f"Your project has {total_deps} total dependencies but only {direct_deps} direct dependencies. "
                    f"This large transitive tree increases attack surface. Consider auditing heavy dependencies."
                ),
                impact={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": total_deps,
                    "total": total_deps,
                },
                affected_components=[f"Total: {total_deps} deps, Direct: {direct_deps} deps"],
                action={
                    "type": "audit_dependencies",
                    "total_deps": total_deps,
                    "direct_deps": direct_deps,
                    "steps": [
                        "Run 'npm ls' or 'pip show' to understand dependency tree",
                        "Identify 'heavy' packages that bring many transitive deps",
                        "Consider lighter alternatives for heavy packages",
                        "Remove unused dependencies",
                        "Use tools like depcheck (npm) to find unused deps",
                    ],
                },
                effort="medium",
            )
        )

    return recommendations
