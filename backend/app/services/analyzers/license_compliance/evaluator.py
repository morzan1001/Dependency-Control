"""License severity evaluation and finding-construction helpers."""

from __future__ import annotations

from functools import partial
from typing import Any

from app.core.constants import get_severity_value
from app.models.finding import Severity
from app.models.license import (
    DeploymentModel,
    DistributionModel,
    LibraryUsage,
    LicenseCategory,
    LicenseInfo,
)
from app.schemas.project import LicensePolicySchema

from .constants import (
    POLICY_VIOLATION_MIN_RANK,
    SPDX_SSPL_1_0,
    UNDETERMINED_LICENSE_ID,
    UNDETERMINED_LICENSE_MESSAGE,
)


def is_acceptable_under_policy(issue: dict[str, Any] | None) -> bool:
    """Whether a consumer could actually take this licence: no finding, or one a policy escape already softened."""
    if issue is None:
        return True
    return get_severity_value(issue["severity"]) < POLICY_VIOLATION_MIN_RANK


def evaluate_license(
    component: dict[str, Any],
    license_info: LicenseInfo,
    policy: LicensePolicySchema,
    lic_url: str | None = None,
) -> dict[str, Any] | None:
    """Return an issue dict if the license is problematic under `policy`, else None."""

    if license_info.category in (
        LicenseCategory.PERMISSIVE,
        LicenseCategory.PUBLIC_DOMAIN,
    ):
        return None

    if license_info.category == LicenseCategory.WEAK_COPYLEFT:
        return evaluate_weak_copyleft(component, license_info, lic_url, policy)

    if license_info.category == LicenseCategory.STRONG_COPYLEFT:
        return evaluate_strong_copyleft(component, license_info, lic_url, policy)

    if license_info.category == LicenseCategory.NETWORK_COPYLEFT:
        return evaluate_network_copyleft(component, license_info, lic_url, policy)

    if license_info.category == LicenseCategory.PROPRIETARY:
        return _issue(
            license_info,
            component,
            lic_url,
            Severity.HIGH,
            "Proprietary or restricted-use license",
            "This license restricts commercial use, production use or derivative works, depending on its terms. "
            "Check them against your use, find an alternative, or obtain a commercial license.",
        )

    return None


def _issue(
    license_info: LicenseInfo,
    component: dict[str, Any],
    lic_url: str | None,
    severity: Severity,
    message: str,
    recommendation: str,
    *,
    explanation: str | None = None,
    reason: str | None = None,
    baseline: Severity | None = None,
) -> dict[str, Any]:
    softened = baseline is not None and get_severity_value(severity.value) < get_severity_value(baseline.value)
    return create_issue(
        component=component,
        license_id=license_info.spdx_id,
        severity=severity,
        category=license_info.category.value,
        message=f"{message}: {license_info.name}",
        explanation=explanation or license_info.description,
        recommendation=recommendation,
        obligations=license_info.obligations,
        risks=license_info.risks,
        license_url=lic_url,
        context_reason=reason,
        severity_without_context=baseline if softened else None,
    )


def evaluate_weak_copyleft(
    component: dict[str, Any],
    license_info: LicenseInfo,
    lic_url: str | None,
    policy: LicensePolicySchema,
) -> dict[str, Any] | None:
    """Weak copyleft (LGPL, MPL, EPL, CDDL): obligation only on modification."""
    if policy.library_usage == LibraryUsage.UNMODIFIED:
        return None

    return _issue(
        license_info,
        component,
        lic_url,
        Severity.INFO,
        "Weak copyleft license",
        "This license allows use in proprietary software, but modifications "
        "to this library must be shared under the same license.",
        reason=(
            "Library is marked as modified — modifications to this library must be shared under the same license."
            if policy.library_usage == LibraryUsage.MODIFIED
            else None
        ),
    )


def evaluate_strong_copyleft(
    component: dict[str, Any],
    license_info: LicenseInfo,
    lic_url: str | None,
    policy: LicensePolicySchema,
) -> dict[str, Any] | None:
    """Strong copyleft (GPL): obligations trigger only upon distribution."""
    issue = partial(_issue, license_info, component, lic_url, baseline=Severity.HIGH)

    if policy.distribution_model == DistributionModel.INTERNAL_ONLY:
        return issue(
            Severity.INFO,
            "Strong copyleft license (internal use only)",
            "This project is internal-only. GPL obligations only apply when "
            "distributing software, so no action is required.",
            reason="Severity reduced: project is internal-only, GPL distribution obligations do not apply.",
        )

    if policy.distribution_model == DistributionModel.OPEN_SOURCE:
        return issue(
            Severity.INFO,
            "Strong copyleft license (open source project)",
            "This project is open source. Ensure your project license is GPL-compatible if distributing.",
            reason="Severity reduced: project is open source, GPL source disclosure is already satisfied.",
        )

    if policy.allow_strong_copyleft:
        return issue(
            Severity.INFO,
            "Strong copyleft license (allowed by policy)",
            "Your policy allows GPL-style licenses. "
            "Ensure compliance with source disclosure requirements if distributing.",
            reason="Severity reduced: project license policy allows strong copyleft.",
        )

    return issue(
        Severity.HIGH,
        "Strong copyleft license",
        "Options:\n"
        "• If not distributing (internal use only): GPL obligations don't apply\n"
        "• If open-sourcing your project: License your code under GPL\n"
        "• Otherwise: Find an alternative package with a permissive license",
        explanation=(
            f"{license_info.description}\n\n"
            "IMPORTANT: If you distribute this software (binary or source), "
            "you must also distribute the complete source code of your "
            "entire application under the GPL."
        ),
    )


def evaluate_network_copyleft(
    component: dict[str, Any],
    license_info: LicenseInfo,
    lic_url: str | None,
    policy: LicensePolicySchema,
) -> dict[str, Any] | None:
    """Network copyleft (AGPL, SSPL): network use triggers source disclosure; distribution does in every deployment."""
    issue = partial(_issue, license_info, component, lic_url, baseline=Severity.CRITICAL)

    if policy.deployment_model in (
        DeploymentModel.CLI_BATCH,
        DeploymentModel.DESKTOP,
        DeploymentModel.EMBEDDED,
    ):
        if policy.distribution_model in (DistributionModel.INTERNAL_ONLY, DistributionModel.OPEN_SOURCE):
            return issue(
                Severity.LOW,
                "Network copyleft license (non-network deployment)",
                "This project does not provide network access to users, so the "
                "AGPL/SSPL network clause does not apply. Standard GPL-like "
                "distribution obligations still apply if distributing.",
                reason=(
                    "Severity reduced: project deployment model is "
                    f"'{policy.deployment_model}', AGPL/SSPL network clause does not apply."
                ),
            )
        if policy.allow_network_copyleft or policy.allow_strong_copyleft:
            return issue(
                Severity.MEDIUM,
                "Network copyleft license (allowed by policy)",
                "Your policy allows copyleft licenses. Distributing this software still requires "
                "publishing the complete source of your application under the same license.",
                reason="Severity reduced: project license policy allows copyleft; the network clause does not apply.",
            )
        return issue(
            Severity.HIGH,
            "Network copyleft license (distributed, non-network deployment)",
            "Options:\n"
            "• If open-sourcing your project: License your code under a compatible license\n"
            "• Otherwise: Find an alternative package with a permissive license",
            explanation=(
                f"{license_info.description}\n\n"
                f"The network clause does not apply to a '{policy.deployment_model}' deployment, but "
                "distributing this software triggers the full copyleft obligations: you must also "
                "distribute the complete source code of your application under the same license."
            ),
            reason="Severity reduced: network clause does not apply; distribution obligations do.",
        )

    # Publishing the project does not satisfy SSPL, whose clause covers the whole service stack.
    if policy.distribution_model == DistributionModel.OPEN_SOURCE and license_info.spdx_id != SPDX_SSPL_1_0:
        return issue(
            Severity.INFO,
            "Network copyleft license (open source project)",
            "Keep the project licence AGPL-compatible and publish the exact source you deploy.",
            reason="Severity reduced: project is open source, AGPL network source offer is satisfied by publication.",
        )

    if policy.distribution_model == DistributionModel.INTERNAL_ONLY:
        return issue(
            Severity.MEDIUM,
            "Network copyleft license (internal service)",
            "This is an internal service. AGPL/SSPL network obligations may "
            "still apply if internal users interact with the software over a "
            "network. Review with legal counsel.",
            reason="Severity reduced: project is internal-only, but network clause may still apply for internal users.",
        )

    if policy.allow_network_copyleft:
        return issue(
            Severity.MEDIUM,
            "Network copyleft license (allowed by policy)",
            "Your policy allows AGPL-style licenses. Remember: providing "
            "network access to users triggers source disclosure.",
            reason=(
                "Severity reduced: project license policy allows network copyleft; "
                "network use still triggers source disclosure."
            ),
        )

    return issue(
        Severity.CRITICAL,
        "Network copyleft license",
        "This license is highly problematic for commercial/proprietary use:\n"
        "• Find an alternative package with a permissive license\n"
        "• If no alternative exists, consider isolating this component "
        "as a separate service\n"
        "• Consult with legal counsel before proceeding",
        explanation=(
            f"{license_info.description}\n\n"
            "[CRITICAL] Unlike GPL, AGPL/SSPL obligations are triggered when "
            "users interact with the software over a network, even if you "
            "never distribute binaries. This affects SaaS, web applications, "
            "and APIs."
        ),
    )


def create_undeterminable_issue(
    component: dict[str, Any],
    unrecognized: list[str],
    rejected_alternatives: list[str] | None = None,
) -> dict[str, Any]:
    """Flag a component whose licence the SBOM does not let us determine, which is not auditable —
    exactly what the audit control means. INFO is deliberate: "we cannot tell" is not the same class
    as a disallowed licence, and the control keys on the finding's presence, not on its severity.
    """
    if unrecognized:
        explanation = (
            f"The SBOM declares {', '.join(unrecognized)} for this component, which is not in the license "
            "catalogue this analyzer evaluates, so its obligations cannot be evaluated."
        )
    else:
        explanation = (
            "The SBOM carries no license information for this component, so its obligations cannot be evaluated."
        )
    if rejected_alternatives:
        explanation += (
            f" The alternatives this expression offers that we can read ({', '.join(rejected_alternatives)}) "
            "are not acceptable under the current license policy, so no readable and acceptable choice remains."
        )
    return create_issue(
        component=component,
        license_id=UNDETERMINED_LICENSE_ID,
        severity=Severity.INFO,
        category=LicenseCategory.UNKNOWN.value,
        message=UNDETERMINED_LICENSE_MESSAGE,
        explanation=explanation,
        recommendation=(
            "Add a license override for this component, pin it to a release that declares its "
            "license, or remove the dependency."
        ),
    )


def apply_transitive_adjustment(issue: dict[str, Any], is_transitive: bool) -> None:
    """Downgrade one severity level for transitive deps, whose copyleft obligations may be abstracted away."""
    if not is_transitive:
        return

    issue["is_transitive"] = True
    severity = issue.get("severity")

    downgrade_map = {
        Severity.CRITICAL.value: Severity.HIGH.value,
        Severity.HIGH.value: Severity.MEDIUM.value,
        Severity.MEDIUM.value: Severity.LOW.value,
    }
    new_severity = downgrade_map.get(severity) if isinstance(severity, str) else None
    if new_severity:
        issue["severity_without_context"] = issue.get("severity_without_context") or severity
        issue["severity"] = new_severity
        existing_reason = issue.get("context_reason", "")
        transitive_note = "Severity reduced: transitive dependency (not directly included)."
        issue["context_reason"] = f"{existing_reason} {transitive_note}".strip() if existing_reason else transitive_note


def should_include_finding(issue: dict[str, Any], is_transitive: bool) -> bool:
    """Skip INFO/LOW transitive findings — noise without actionable value."""
    return not (is_transitive and issue.get("severity") in (Severity.INFO.value, Severity.LOW.value))


def create_issue(
    component: dict[str, Any],
    license_id: str,
    severity: Severity,
    category: str,
    message: str,
    explanation: str,
    recommendation: str,
    obligations: list[str] | None = None,
    risks: list[str] | None = None,
    license_url: str | None = None,
    context_reason: str | None = None,
    severity_without_context: Severity | None = None,
) -> dict[str, Any]:
    """Create a license issue dict for the component whose name, version and purl it carries."""
    issue: dict[str, Any] = {
        "component": component.get("name", "unknown"),
        "version": component.get("version", "unknown"),
        "license": license_id,
        "license_url": license_url,
        "severity": severity.value,
        "category": category,
        "message": message,
        "explanation": explanation,
        "recommendation": recommendation,
        "obligations": obligations or [],
        "risks": risks or [],
        "purl": component.get("purl", ""),
    }
    if context_reason:
        issue["context_reason"] = context_reason
    if severity_without_context:
        issue["severity_without_context"] = severity_without_context.value
    return issue
