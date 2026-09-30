"""License Audit: evaluates SBOM licenses against the project license policy."""

from typing import Any

from app.models.finding import FindingType, Severity
from app.models.license import DistributionModel, LicenseCategory
from app.schemas.compliance import (
    ControlResult,
    ControlStatus,
    FrameworkEvaluation,
    ReportFramework,
)
from app.services.analyzers.license_compliance.constants import LICENSE_INCOMPATIBILITY_CATEGORY
from app.services.compliance.frameworks.base import (
    EvaluationInput,
    _classify,
    _waiver_reasons,
    build_evaluation,
)

_REPLACE_OR_ALLOW = (
    "Replace or remove components under disallowed licenses, "
    "or explicitly flip the corresponding policy toggle if "
    "the usage context permits."
)

# Each control fails on unwaived license findings of its category; `skip` names what exempts it.
_CONTROLS: tuple[dict[str, Any], ...] = (
    {
        "control_id": "LICENSE-AUDIT-STRONG-COPYLEFT",
        "title": "No strong-copyleft licenses",
        "description": (
            "Strong-copyleft licenses (GPL-family) impose source-disclosure "
            "obligations when the project is distributed. Policy forbids them."
        ),
        "category": LicenseCategory.STRONG_COPYLEFT.value,
        "severity": Severity.HIGH,
        "skip": lambda policy: "policy allows" if policy.allow_strong_copyleft else None,
        "remediation": _REPLACE_OR_ALLOW,
    },
    {
        "control_id": "LICENSE-AUDIT-NETWORK-COPYLEFT",
        "title": "No network-copyleft licenses",
        "description": (
            "Network-copyleft licenses (AGPL, SSPL) trigger disclosure obligations on network use. Policy forbids them."
        ),
        "category": LicenseCategory.NETWORK_COPYLEFT.value,
        "severity": Severity.HIGH,
        "skip": lambda policy: "policy allows" if policy.allow_network_copyleft else None,
        "remediation": _REPLACE_OR_ALLOW,
    },
    {
        "control_id": "LICENSE-AUDIT-NO-PROPRIETARY",
        "title": "No non-commercial / proprietary licenses",
        "description": "Non-commercial and proprietary licenses restrict every use of a component, internal use included.",
        "category": LicenseCategory.PROPRIETARY.value,
        "severity": Severity.HIGH,
        "skip": lambda policy: None,
        "remediation": "Replace each flagged component or obtain a commercial license for it.",
    },
    {
        "control_id": "LICENSE-AUDIT-LICENSE-COMPATIBILITY",
        "title": "No incompatible license combinations",
        "description": "Licenses whose terms conflict cannot be combined in one distributed work.",
        "category": LICENSE_INCOMPATIBILITY_CATEGORY,
        "severity": Severity.HIGH,
        "skip": lambda policy: (
            "internal-only distribution" if policy.distribution_model == DistributionModel.INTERNAL_ONLY else None
        ),
        "remediation": "Replace one component of each conflicting pair, or relicense it where its authors allow.",
    },
    {
        "control_id": "LICENSE-AUDIT-LICENSE-IDENTIFIED",
        "title": "All components have identified licenses",
        "description": "Components without a known license cannot be audited; this control flags those.",
        "category": LicenseCategory.UNKNOWN.value,
        "severity": Severity.MEDIUM,
        "skip": lambda policy: None,
        "remediation": (
            "Inspect each flagged component: add a license override, "
            "pin to a versioned release with declared metadata, or "
            "remove the dependency."
        ),
    },
)

LICENSE_AUDIT_CATEGORIES: tuple[str, ...] = tuple(cfg["category"] for cfg in _CONTROLS)


class LicenseAuditFramework:
    key: ReportFramework = ReportFramework.LICENSE_AUDIT
    name: str = "License Audit (project policy)"
    version: str = "1"
    disclaimer: str | None = (
        "This report checks the project's SBOM dependencies against the "
        "configured license policy: the copyleft toggles, the distribution "
        "model, proprietary and unidentified licenses, and incompatible "
        "license combinations. It is an advisory signal, not legal advice."
    )

    async def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        controls: list[ControlResult] = []
        for cfg in _CONTROLS:
            if note := cfg["skip"](data.license_policy):
                controls.append(
                    ControlResult(
                        control_id=cfg["control_id"],
                        title=cfg["title"],
                        description=f"{cfg['description']} ({note}; skipped)",
                        status=ControlStatus.NOT_APPLICABLE,
                        severity=cfg["severity"],
                        evidence_finding_ids=[],
                        evidence_asset_bom_refs=[],
                        waiver_reasons=[],
                        remediation="",
                    )
                )
                continue
            matching = [f for f in data.findings if _is_license_violation(f, cfg["category"])]
            status, evidence, status_reason = _classify(matching, data.coverage)
            controls.append(
                ControlResult(
                    control_id=cfg["control_id"],
                    title=cfg["title"],
                    description=cfg["description"],
                    status=status,
                    severity=cfg["severity"],
                    evidence_finding_ids=evidence,
                    evidence_asset_bom_refs=[],
                    waiver_reasons=_waiver_reasons(matching),
                    remediation=cfg["remediation"],
                    status_reason=status_reason,
                )
            )

        return build_evaluation(
            self,
            data,
            controls,
            coverage=data.coverage,
            extra_inputs=(f"license_policy={data.license_policy.model_dump_json()}",),
        )


def _is_license_violation(f: dict[str, Any], category: str) -> bool:
    # The license normalizer passes the scanner's category through as details.category.
    return f.get("type") == FindingType.LICENSE.value and (f.get("details") or {}).get("category") == category
