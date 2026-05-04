"""
License Audit — SBOM-side compliance "framework".

Evaluates the project's SBOM dependencies against its current license
policy (``project.license_policy`` or ``analyzer_settings.license_compliance``).
Each license category gets one control; findings with
``FindingType.LICENSE_VIOLATION`` drive the FAILED/PASSED verdict.

Async-only — the evaluator loads findings from MongoDB via EvaluationInput.
Callers must dispatch on ``hasattr(framework, 'evaluate_async')``.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.models.finding import FindingType, Severity
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    FrameworkEvaluation,
    ReportFramework,
)
from app.services.compliance.frameworks.base import (
    EvaluationInput,
    build_residual_risks,
    build_summary,
    extract_finding_id,
)


# Licence-policy setting keys and the control they expand to. The key
# points to the boolean on the resolved policy; when False, any finding
# with the corresponding license_category becomes a FAILED control.
_POLICY_TO_CATEGORY: Dict[str, Dict[str, Any]] = {
    "allow_strong_copyleft": {
        "control_id": "LICENSE-AUDIT-STRONG-COPYLEFT",
        "title": "No strong-copyleft licenses",
        "description": (
            "Strong-copyleft licenses (GPL-family) impose source-disclosure "
            "obligations when the project is distributed. Policy forbids them."
        ),
        "categories": ["strong_copyleft"],
        "severity": Severity.HIGH,
    },
    "allow_network_copyleft": {
        "control_id": "LICENSE-AUDIT-NETWORK-COPYLEFT",
        "title": "No network-copyleft licenses",
        "description": (
            "Network-copyleft licenses (AGPL, SSPL) trigger disclosure obligations on network use. Policy forbids them."
        ),
        "categories": ["network_copyleft"],
        "severity": Severity.HIGH,
    },
}


class LicenseAuditFramework:
    key: ReportFramework = ReportFramework.LICENSE_AUDIT
    name: str = "License Audit (project policy)"
    version: str = "1"
    source_url: str = "https://spdx.dev/learn/handling-license-info/"
    disclaimer: Optional[str] = (
        "This report checks the project's SBOM dependencies against the "
        "configured license policy (allow_strong_copyleft / "
        "allow_network_copyleft etc.). It is an advisory signal, not legal "
        "advice."
    )
    controls: List[ControlDefinition] = []

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        raise RuntimeError("LicenseAuditFramework is async-only; callers must dispatch via evaluate_async()")

    async def evaluate_async(self, data: EvaluationInput) -> FrameworkEvaluation:
        policy = _extract_license_policy(data)
        findings = data.findings or []

        controls: List[ControlResult] = []
        for policy_key, cfg in _POLICY_TO_CATEGORY.items():
            allowed = bool(policy.get(policy_key, False))
            if allowed:
                # The policy explicitly permits this category — control is
                # NOT_APPLICABLE because we deliberately tolerate it.
                controls.append(
                    ControlResult(
                        control_id=cfg["control_id"],
                        title=cfg["title"],
                        description=f"{cfg['description']} (policy allows; skipped)",
                        status=ControlStatus.NOT_APPLICABLE,
                        severity=cfg["severity"],
                        evidence_finding_ids=[],
                        evidence_asset_bom_refs=[],
                        waiver_reasons=[],
                        remediation="",
                    )
                )
                continue
            matching = [f for f in findings if _is_license_violation(f, cfg["categories"])]
            status, evidence = _classify(matching)
            controls.append(
                ControlResult(
                    control_id=cfg["control_id"],
                    title=cfg["title"],
                    description=cfg["description"],
                    status=status,
                    severity=cfg["severity"],
                    evidence_finding_ids=evidence,
                    evidence_asset_bom_refs=[],
                    waiver_reasons=[_waiver_reason(f) for f in matching if f.get("waived")],
                    remediation=(
                        "Replace or remove components under disallowed licenses, "
                        "or explicitly flip the corresponding policy toggle if "
                        "the usage context permits."
                    ),
                )
            )

        # "All components have an identified license" — catch-all hygiene
        unknown = [f for f in findings if _is_license_violation(f, ["unknown"])]
        status, evidence = _classify(unknown)
        controls.append(
            ControlResult(
                control_id="LICENSE-AUDIT-LICENSE-IDENTIFIED",
                title="All components have identified licenses",
                description=("Components without a known license cannot be audited; this control flags those."),
                status=status,
                severity=Severity.MEDIUM,
                evidence_finding_ids=evidence,
                evidence_asset_bom_refs=[],
                waiver_reasons=[_waiver_reason(f) for f in unknown if f.get("waived")],
                remediation=(
                    "Inspect each flagged component: add a license override, "
                    "pin to a versioned release with declared metadata, or "
                    "remove the dependency."
                ),
            )
        )

        return FrameworkEvaluation(
            framework_key=self.key,
            framework_name=self.name,
            framework_version=self.version,
            generated_at=datetime.now(timezone.utc),
            scope_description=data.scope_description,
            controls=controls,
            summary=build_summary(controls),
            residual_risks=build_residual_risks(controls),
            inputs_fingerprint="license-audit-v1",
        )


def _extract_license_policy(data: EvaluationInput) -> Dict[str, Any]:
    """Pull the license policy from EvaluationInput's policy_rules dump.

    Falls back to permissive defaults when the policy isn't set.
    """
    rules = data.policy_rules or []
    # EvaluationInput.policy_rules is a list of dicts. License policy is
    # stored as a single dict (flat, not rule-based), so the convention
    # used by compliance endpoints is to place it as the first element
    # when license framework is targeted.
    if rules and isinstance(rules[0], dict):
        first = rules[0]
        if any(k in first for k in ("allow_strong_copyleft", "allow_network_copyleft", "distribution_model")):
            return first
    return {}


def _is_license_violation(f: Dict[str, Any], categories: List[str]) -> bool:
    ftype = f.get("type")
    license_type = FindingType.LICENSE.value
    if ftype != license_type:
        return False
    details = f.get("details") or {}
    observed_category = details.get("license_category")
    return observed_category in categories


def _classify(matching: List[Dict[str, Any]]) -> tuple[ControlStatus, List[str]]:
    if not matching:
        return ControlStatus.PASSED, []
    active = [f for f in matching if not f.get("waived")]
    evidence_ids = [extract_finding_id(f) for f in matching if f.get("_id") or f.get("id")]
    if active:
        return ControlStatus.FAILED, evidence_ids
    return ControlStatus.WAIVED, evidence_ids


def _waiver_reason(f: Dict[str, Any]) -> str:
    return str(f.get("waiver_reason") or "")
