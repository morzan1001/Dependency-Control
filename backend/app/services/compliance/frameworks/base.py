"""
Common framework machinery.

`ComplianceFramework` is a Protocol-style interface. Concrete implementations
live in sibling modules; each defines its control list + optional custom
evaluators and delegates everything else to the default evaluator here.
"""

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_asset import CryptoAsset
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    FrameworkEvaluation,
    ReportFramework,
    ResidualRisk,
)
from app.schemas.crypto_policy import CryptoRule
from app.services.analytics.scopes import ResolvedScope
from app.services.analyzers.crypto.matcher import asset_in_rule_scope

logger = logging.getLogger(__name__)


@dataclass
class EvaluationInput:
    """Data bag passed into framework.evaluate()."""

    resolved: ResolvedScope
    scope_description: str
    crypto_assets: List[CryptoAsset]
    findings: List[dict]  # persisted finding docs (kept dict for flexibility)
    policy_rules: List[dict]  # CryptoRule dumps from the effective policy
    policy_version: Optional[int]
    iana_catalog_version: Optional[int]
    scan_ids: List[str]
    # Populated by engine._gather_inputs for meta-frameworks that need to run
    # their own queries (e.g. PQC migration plan delegates to a generator).
    # Typed precisely so consumers (notably PQC) don't need runtime casts.
    db: Optional[AsyncIOMotorDatabase[Any]] = None


@runtime_checkable
class ComplianceFramework(Protocol):
    """Interface every framework must implement."""

    name: str
    key: ReportFramework
    version: str
    source_url: str

    @property
    def disclaimer(self) -> Optional[str]:  # shown on report cover (e.g. FIPS)
        ...

    @property
    def controls(self) -> List[ControlDefinition]: ...

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation: ...


def default_evaluator(
    control: ControlDefinition,
    data: EvaluationInput,
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
        if not any(ft == (t.value if hasattr(t, "value") else t) for t in control.maps_to_finding_types):
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
        evidence_finding_ids=[extract_finding_id(f) for f in matching],
        evidence_asset_bom_refs=_extract_bom_refs(matching),
        waiver_reasons=[(f.get("waiver_reason") or "") for f in waived_findings if f.get("waiver_reason")],
        remediation=control.remediation,
    )


def _rules_for_control(
    control: ControlDefinition,
    policy_rules: List[dict],
) -> List[CryptoRule]:
    """Reconstruct the CryptoRule objects this control maps to, from the
    system-policy dumps in EvaluationInput.policy_rules. Rules absent from the
    policy (or unparseable) are skipped."""
    if not control.maps_to_rule_ids:
        return []
    wanted = set(control.maps_to_rule_ids)
    rules: List[CryptoRule] = []
    for raw in policy_rules:
        if raw.get("rule_id") in wanted:
            try:
                rules.append(CryptoRule.model_validate(raw))
            except Exception:  # pragma: no cover - defensive against malformed dumps
                continue
    return rules


def _is_applicable(
    control: ControlDefinition,
    data: EvaluationInput,
) -> bool:
    """A control is applicable (eligible for PASSED) only when its subject is
    actually present in the inventory: at least one crypto asset falls within the
    scope of one of the control's mapped rules. Threshold criteria (e.g. minimum
    key size) are ignored here — a COMPLIANT asset still makes the control
    applicable so it can legitimately PASS.

    Without this, a control whose primitive is absent (e.g. an RSA-key-size
    control on an AES-only project) would report a false PASSED.

    Falls back to inventory presence when the control's rules cannot be resolved
    from the system policy (e.g. finding-type-only controls), so controls are
    never silently hidden."""
    if not data.crypto_assets:
        return False
    rules = _rules_for_control(control, data.policy_rules)
    if not rules:
        # A control that declares rule_ids but resolves none indicates policy
        # drift (rule removed/renamed); warn rather than silently degrade to the
        # any-asset fallback (audit SC#4).
        if control.maps_to_rule_ids:
            logger.warning(
                "compliance: control %s maps to rule_ids %s but none resolve from the system "
                "policy; falling back to inventory presence (possible policy drift)",
                control.control_id,
                control.maps_to_rule_ids,
            )
        return True  # cannot scope to a primitive -> preserve inventory-presence behavior
    return any(asset_in_rule_scope(asset, rule) for asset in data.crypto_assets for rule in rules)


def _extract_bom_refs(findings: List[dict]) -> List[str]:
    refs: List[str] = []
    for f in findings:
        details = f.get("details") or {}
        if ref := details.get("bom_ref"):
            refs.append(ref)
    return sorted(set(refs))


def evaluate_framework(
    framework: ComplianceFramework,
    data: EvaluationInput,
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


def status_value(status: Any) -> str:
    """Return the plain-string form of a ControlStatus / Severity / etc.

    Centralises the ``x.value if hasattr(x, 'value') else x`` pattern that
    otherwise gets repeated across every framework and renderer.  Accepts
    enums, plain strings, or None (returns empty string).
    """
    if status is None:
        return ""
    return status.value if hasattr(status, "value") else str(status)


def extract_finding_id(finding: Dict[str, Any]) -> str:
    """Best-effort finding ID accessor with _id/id fallback.

    Findings sourced from MongoDB carry ``_id``; in-memory test dicts
    sometimes carry ``id``. Returns '' when neither is present.
    """
    return str(finding.get("_id") or finding.get("id") or "")


def build_summary(results: List[ControlResult]) -> Dict[str, int]:
    """Count controls by status bucket (shared across frameworks)."""
    counts = {"passed": 0, "failed": 0, "waived": 0, "not_applicable": 0, "total": len(results)}
    for r in results:
        key = status_value(r.status)
        counts[key] = counts.get(key, 0) + 1
    return counts


def build_residual_risks(results: List[ControlResult]) -> List[ResidualRisk]:
    """Convert every FAILED ControlResult into a ResidualRisk entry."""
    return [
        ResidualRisk(
            control_id=r.control_id,
            title=r.title,
            severity=r.severity,
            description=r.description,
        )
        for r in results
        if status_value(r.status) == "failed"
    ]


# Private aliases kept for backwards compatibility with existing callers
# inside this module.
_build_summary = build_summary
_build_residual_risks = build_residual_risks


def _inputs_fingerprint(data: EvaluationInput) -> str:
    bits = "|".join(
        [
            f"policy={data.policy_version}",
            f"iana={data.iana_catalog_version}",
            f"scans={','.join(sorted(data.scan_ids))}",
        ]
    )
    return "sha256:" + hashlib.sha256(bits.encode()).hexdigest()
