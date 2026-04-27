"""License severity evaluation and finding-construction helpers.

Pure functions that translate a single :class:`LicenseInfo` plus a project
:class:`LicensePolicy` into an issue dictionary (or ``None`` if no finding
applies). Also contains transitive-severity adjustment, the severity-based
finding filter, and the issue-dict factory.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.models.finding import Severity
from app.models.license import (
    DeploymentModel,
    DistributionModel,
    LibraryUsage,
    LicenseCategory,
    LicenseInfo,
    LicensePolicy,
)


def evaluate_license(
    component: str,
    version: str,
    license_info: LicenseInfo,
    lic_url: Optional[str],
    purl: str,
    policy: LicensePolicy,
) -> Optional[Dict[str, Any]]:
    """Evaluate a license and return an issue if problematic.

    Severity is determined by the license category and the project's license policy.
    When a policy reduces the severity, ``context_reason`` and ``effective_severity``
    fields are added to the issue for auditability.
    """

    # Permissive and public domain are always fine
    if license_info.category in (
        LicenseCategory.PERMISSIVE,
        LicenseCategory.PUBLIC_DOMAIN,
    ):
        return None

    # Weak copyleft — context: only relevant when library is modified
    if license_info.category == LicenseCategory.WEAK_COPYLEFT:
        return evaluate_weak_copyleft(component, version, license_info, lic_url, purl, policy)

    # Strong copyleft — context: only relevant when distributing
    if license_info.category == LicenseCategory.STRONG_COPYLEFT:
        return evaluate_strong_copyleft(component, version, license_info, lic_url, purl, policy)

    # Network copyleft — context: only relevant for network-facing services
    if license_info.category == LicenseCategory.NETWORK_COPYLEFT:
        return evaluate_network_copyleft(component, version, license_info, lic_url, purl, policy)

    # Proprietary (e.g., NC licenses) — always problematic regardless of context
    if license_info.category == LicenseCategory.PROPRIETARY:
        return create_issue(
            component=component,
            version=version,
            license_id=license_info.spdx_id,
            severity=Severity.HIGH,
            category=license_info.category,
            message=f"Non-commercial or proprietary license: {license_info.name}",
            explanation=license_info.description,
            recommendation=(
                "This package cannot be used in commercial products. "
                "Find an alternative or obtain a commercial license."
            ),
            obligations=license_info.obligations,
            purl=purl,
            license_url=lic_url,
        )

    return None


def evaluate_weak_copyleft(
    component: str,
    version: str,
    license_info: LicenseInfo,
    lic_url: Optional[str],
    purl: str,
    policy: LicensePolicy,
) -> Optional[Dict[str, Any]]:
    """Evaluate weak copyleft licenses (LGPL, MPL, EPL, CDDL).

    Weak copyleft only requires source disclosure for modifications to the library
    itself. Using a library as-is via its public API creates no copyleft obligation.
    """
    if policy.library_usage == LibraryUsage.UNMODIFIED:
        # No obligation when using as-is — skip finding entirely
        return None

    context_reason = None
    if policy.library_usage == LibraryUsage.MODIFIED:
        context_reason = (
            "Library is marked as modified — modifications to this library must be shared under the same license."
        )

    return create_issue(
        component=component,
        version=version,
        license_id=license_info.spdx_id,
        severity=Severity.INFO,
        category=license_info.category,
        message=f"Weak copyleft license: {license_info.name}",
        explanation=license_info.description,
        recommendation=(
            "This license allows use in proprietary software, but modifications "
            "to this library must be shared under the same license."
        ),
        obligations=license_info.obligations,
        purl=purl,
        license_url=lic_url,
        context_reason=context_reason,
    )


def evaluate_strong_copyleft(
    component: str,
    version: str,
    license_info: LicenseInfo,
    lic_url: Optional[str],
    purl: str,
    policy: LicensePolicy,
) -> Optional[Dict[str, Any]]:
    """Evaluate strong copyleft licenses (GPL).

    GPL obligations only trigger upon distribution. Internal-only tools and
    open-source projects have no GPL compliance risk.
    """
    # Internal-only: GPL obligations don't apply (no distribution)
    if policy.distribution_model == DistributionModel.INTERNAL_ONLY:
        return create_issue(
            component=component,
            version=version,
            license_id=license_info.spdx_id,
            severity=Severity.INFO,
            category=license_info.category,
            message=f"Strong copyleft license (internal use only): {license_info.name}",
            explanation=license_info.description,
            recommendation=(
                "This project is internal-only. GPL obligations only apply when "
                "distributing software, so no action is required."
            ),
            obligations=license_info.obligations,
            purl=purl,
            license_url=lic_url,
            context_reason=(
                "Severity reduced: project is internal-only, GPL distribution obligations do not apply."
            ),
            effective_severity=Severity.HIGH.value,
        )

    # Open source: GPL is fine, code is already open
    if policy.distribution_model == DistributionModel.OPEN_SOURCE:
        return create_issue(
            component=component,
            version=version,
            license_id=license_info.spdx_id,
            severity=Severity.INFO,
            category=license_info.category,
            message=f"Strong copyleft license (open source project): {license_info.name}",
            explanation=license_info.description,
            recommendation=(
                "This project is open source. Ensure your project license is GPL-compatible if distributing."
            ),
            obligations=license_info.obligations,
            purl=purl,
            license_url=lic_url,
            context_reason=(
                "Severity reduced: project is open source, GPL source disclosure is already satisfied."
            ),
            effective_severity=Severity.HIGH.value,
        )

    # Distributed: depends on policy allowance
    if policy.allow_strong_copyleft:
        return create_issue(
            component=component,
            version=version,
            license_id=license_info.spdx_id,
            severity=Severity.INFO,
            category=license_info.category,
            message=f"Strong copyleft license (allowed by policy): {license_info.name}",
            explanation=license_info.description,
            recommendation=(
                "Your policy allows GPL-style licenses. "
                "Ensure compliance with source disclosure requirements if distributing."
            ),
            obligations=license_info.obligations,
            purl=purl,
            license_url=lic_url,
        )

    return create_issue(
        component=component,
        version=version,
        license_id=license_info.spdx_id,
        severity=Severity.HIGH,
        category=license_info.category,
        message=f"Strong copyleft license: {license_info.name}",
        explanation=(
            f"{license_info.description}\n\n"
            "IMPORTANT: If you distribute this software (binary or source), "
            "you must also distribute the complete source code of your "
            "entire application under the GPL."
        ),
        recommendation=(
            "Options:\n"
            "• If not distributing (internal use only): GPL obligations don't apply\n"
            "• If open-sourcing your project: License your code under GPL\n"
            "• Otherwise: Find an alternative package with a permissive license"
        ),
        obligations=license_info.obligations,
        risks=license_info.risks,
        purl=purl,
        license_url=lic_url,
    )


def evaluate_network_copyleft(
    component: str,
    version: str,
    license_info: LicenseInfo,
    lic_url: Optional[str],
    purl: str,
    policy: LicensePolicy,
) -> Optional[Dict[str, Any]]:
    """Evaluate network copyleft licenses (AGPL, SSPL).

    AGPL/SSPL obligations trigger when users interact over a network.
    CLI tools, batch jobs, desktop apps, and embedded systems are not affected.
    """
    # Non-network deployment: AGPL network clause is irrelevant
    if policy.deployment_model in (
        DeploymentModel.CLI_BATCH,
        DeploymentModel.DESKTOP,
        DeploymentModel.EMBEDDED,
    ):
        return create_issue(
            component=component,
            version=version,
            license_id=license_info.spdx_id,
            severity=Severity.LOW,
            category=license_info.category,
            message=f"Network copyleft license (non-network deployment): {license_info.name}",
            explanation=license_info.description,
            recommendation=(
                "This project does not provide network access to users, so the "
                "AGPL/SSPL network clause does not apply. Standard GPL-like "
                "distribution obligations still apply if distributing."
            ),
            obligations=license_info.obligations,
            purl=purl,
            license_url=lic_url,
            context_reason=(
                "Severity reduced: project deployment model is "
                f"'{policy.deployment_model.value}', AGPL/SSPL network clause "
                "does not apply."
            ),
            effective_severity=Severity.CRITICAL.value,
        )

    # Network-facing + internal only: reduced concern
    if policy.distribution_model == DistributionModel.INTERNAL_ONLY:
        return create_issue(
            component=component,
            version=version,
            license_id=license_info.spdx_id,
            severity=Severity.MEDIUM,
            category=license_info.category,
            message=f"Network copyleft license (internal service): {license_info.name}",
            explanation=license_info.description,
            recommendation=(
                "This is an internal service. AGPL/SSPL network obligations may "
                "still apply if internal users interact with the software over a "
                "network. Review with legal counsel."
            ),
            obligations=license_info.obligations,
            risks=license_info.risks,
            purl=purl,
            license_url=lic_url,
            context_reason=(
                "Severity reduced: project is internal-only, but network clause may still apply for internal users."
            ),
            effective_severity=Severity.CRITICAL.value,
        )

    # Network-facing + distributed: depends on policy allowance
    if policy.allow_network_copyleft:
        return create_issue(
            component=component,
            version=version,
            license_id=license_info.spdx_id,
            severity=Severity.MEDIUM,
            category=license_info.category,
            message=f"Network copyleft license (allowed by policy): {license_info.name}",
            explanation=license_info.description,
            recommendation=(
                "Your policy allows AGPL-style licenses. Remember: providing "
                "network access to users triggers source disclosure."
            ),
            obligations=license_info.obligations,
            purl=purl,
            license_url=lic_url,
        )

    return create_issue(
        component=component,
        version=version,
        license_id=license_info.spdx_id,
        severity=Severity.CRITICAL,
        category=license_info.category,
        message=f"Network copyleft license: {license_info.name}",
        explanation=(
            f"{license_info.description}\n\n"
            "[CRITICAL] Unlike GPL, AGPL/SSPL obligations are triggered when "
            "users interact with the software over a network, even if you "
            "never distribute binaries. This affects SaaS, web applications, "
            "and APIs."
        ),
        recommendation=(
            "This license is highly problematic for commercial/proprietary use:\n"
            "• Find an alternative package with a permissive license\n"
            "• If no alternative exists, consider isolating this component "
            "as a separate service\n"
            "• Consult with legal counsel before proceeding"
        ),
        obligations=license_info.obligations,
        risks=license_info.risks,
        purl=purl,
        license_url=lic_url,
    )


def apply_transitive_adjustment(issue: Dict[str, Any], is_transitive: bool) -> None:
    """Reduce severity for transitive dependencies.

    Transitive dependencies pose less direct risk because:
    - The direct dependency may abstract away the transitive's license obligations
    - Dynamic linking/usage patterns may not trigger copyleft
    """
    if not is_transitive:
        return

    issue["is_transitive"] = True
    severity = issue.get("severity")

    # Downgrade severity by one level for transitive deps
    downgrade_map = {
        Severity.CRITICAL.value: Severity.HIGH.value,
        Severity.HIGH.value: Severity.MEDIUM.value,
        Severity.MEDIUM.value: Severity.LOW.value,
    }
    new_severity = downgrade_map.get(severity) if isinstance(severity, str) else None
    if new_severity:
        issue["effective_severity"] = issue.get("effective_severity") or severity
        issue["severity"] = new_severity
        existing_reason = issue.get("context_reason", "")
        transitive_note = "Severity reduced: transitive dependency (not directly included)."
        issue["context_reason"] = (
            f"{existing_reason} {transitive_note}".strip() if existing_reason else transitive_note
        )


def should_include_finding(issue: Dict[str, Any], is_transitive: bool) -> bool:
    """Determine if a finding should be included in results.

    Skip INFO-level findings for transitive dependencies — they add noise
    without actionable value.
    """
    if is_transitive and issue.get("severity") in (
        Severity.INFO.value,
        Severity.LOW.value,
    ):
        return False
    return True


def create_issue(
    component: str,
    version: str,
    license_id: str,
    severity: Severity,
    category: LicenseCategory,
    message: str,
    explanation: str,
    recommendation: str,
    obligations: Optional[List[str]] = None,
    risks: Optional[List[str]] = None,
    purl: Optional[str] = None,
    license_url: Optional[str] = None,
    context_reason: Optional[str] = None,
    effective_severity: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a license issue with full context.

    Args:
        context_reason: Why the severity was adjusted based on project context.
        effective_severity: What the severity would be without project context (audit trail).
    """
    issue: Dict[str, Any] = {
        "component": component,
        "version": version,
        "license": license_id,
        "license_url": license_url,
        "severity": severity.value,
        "category": category.value,
        "message": message,
        "explanation": explanation,
        "recommendation": recommendation,
        "obligations": obligations or [],
        "risks": risks or [],
        "purl": purl,
    }
    if context_reason:
        issue["context_reason"] = context_reason
    if effective_severity:
        issue["effective_severity"] = effective_severity
    return issue
