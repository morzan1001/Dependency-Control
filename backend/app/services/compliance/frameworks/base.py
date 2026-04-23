"""
Common framework machinery.

`ComplianceFramework` is a Protocol-style interface. Concrete implementations
live in sibling modules; each defines its control list + optional custom
evaluators and delegates everything else to the default evaluator here.
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Protocol

from app.models.crypto_asset import CryptoAsset
from app.models.finding import Finding, FindingType, Severity
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    FrameworkEvaluation,
    ReportFramework,
    ResidualRisk,
)
from app.services.analytics.scopes import ResolvedScope


@dataclass
class EvaluationInput:
    """Data bag passed into framework.evaluate()."""
    resolved: ResolvedScope
    scope_description: str
    crypto_assets: List[CryptoAsset]
    findings: List[dict]              # persisted finding docs (kept dict for flexibility)
    policy_rules: List[dict]          # CryptoRule dumps from the effective policy
    policy_version: Optional[int]
    iana_catalog_version: Optional[int]
    scan_ids: List[str]


class ComplianceFramework(Protocol):
    """Interface every framework must implement."""
    name: str
    key: ReportFramework
    version: str
    source_url: str
    disclaimer: Optional[str]         # shown on report cover (e.g. FIPS)
    controls: List[ControlDefinition]

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation: ...


def default_evaluator(
    control: ControlDefinition, data: EvaluationInput,
) -> ControlResult:
    """Default rule-based evaluator.

    Control is FAILED if any non-waived finding exists whose type is in
    `maps_to_finding_types` AND whose rule_id is in `maps_to_rule_ids`
    (if that list is non-empty).

    If all matching findings are waived -> WAIVED. If no crypto assets of the
    relevant primitive/asset-type exist -> NOT_APPLICABLE. Otherwise PASSED.
    """
    matching: List[dict] = []
    for f in data.findings:
        ft = f.get("type")
        if not any(
            ft == (t.value if hasattr(t, "value") else t)
            for t in control.maps_to_finding_types
        ):
            continue
        if control.maps_to_rule_ids:
            details = f.get("details") or {}
            rule_id = details.get("rule_id")
            if rule_id not in control.maps_to_rule_ids:
                continue
        matching.append(f)

    waived_findings = [f for f in matching if f.get("waived")]
    active_findings = [f for f in matching if not f.get("waived")]

    if active_findings:
        status = ControlStatus.FAILED
    elif waived_findings:
        status = ControlStatus.WAIVED
    elif _is_applicable(control, data):
        status = ControlStatus.PASSED
    else:
        status = ControlStatus.NOT_APPLICABLE

    return ControlResult(
        control_id=control.control_id,
        title=control.title,
        description=control.description,
        status=status,
        severity=control.severity,
        evidence_finding_ids=[str(f.get("_id") or f.get("id") or "") for f in matching],
        evidence_asset_bom_refs=_extract_bom_refs(matching),
        waiver_reasons=[
            (f.get("waiver_reason") or "") for f in waived_findings if f.get("waiver_reason")
        ],
        remediation=control.remediation,
    )


def _is_applicable(
    control: ControlDefinition, data: EvaluationInput,
) -> bool:
    """Heuristic: if no assets exist for this framework's scope,
    mark as NOT_APPLICABLE instead of PASSED. Currently we consider the
    control applicable if there are any crypto_assets at all - more
    sophisticated per-primitive filtering can be added later."""
    return bool(data.crypto_assets)


def _extract_bom_refs(findings: List[dict]) -> List[str]:
    refs: List[str] = []
    for f in findings:
        details = f.get("details") or {}
        if ref := details.get("bom_ref"):
            refs.append(ref)
    return sorted(set(refs))


def evaluate_framework(
    framework: ComplianceFramework, data: EvaluationInput,
) -> FrameworkEvaluation:
    """Shared entry point: run every control and build the top-level
    FrameworkEvaluation. Framework modules call this from their `evaluate`."""
    control_results: List[ControlResult] = []
    for control in framework.controls:
        if control.custom_evaluator is not None:
            result = control.custom_evaluator(data)
        else:
            result = default_evaluator(control, data)
        control_results.append(result)

    summary = _build_summary(control_results)
    residuals = _build_residual_risks(control_results)
    fingerprint = _inputs_fingerprint(data)
    return FrameworkEvaluation(
        framework_key=framework.key,
        framework_name=framework.name,
        framework_version=framework.version,
        generated_at=datetime.now(timezone.utc),
        scope_description=data.scope_description,
        controls=control_results,
        summary=summary,
        residual_risks=residuals,
        inputs_fingerprint=fingerprint,
    )


def _build_summary(results: List[ControlResult]) -> Dict[str, int]:
    counts = {"passed": 0, "failed": 0, "waived": 0, "not_applicable": 0, "total": len(results)}
    for r in results:
        key = r.status.value if hasattr(r.status, "value") else r.status
        counts[key] = counts.get(key, 0) + 1
    return counts


def _build_residual_risks(results: List[ControlResult]) -> List[ResidualRisk]:
    return [
        ResidualRisk(
            control_id=r.control_id,
            title=r.title,
            severity=r.severity,
            description=r.description,
        )
        for r in results
        if (r.status.value if hasattr(r.status, "value") else r.status) == "failed"
    ]


def _inputs_fingerprint(data: EvaluationInput) -> str:
    bits = "|".join([
        f"policy={data.policy_version}",
        f"iana={data.iana_catalog_version}",
        f"scans={','.join(sorted(data.scan_ids))}",
    ])
    return "sha256:" + hashlib.sha256(bits.encode()).hexdigest()
