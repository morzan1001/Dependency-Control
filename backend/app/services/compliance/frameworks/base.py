"""Common framework machinery: the ComplianceFramework protocol and default evaluator."""

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
    resolved: ResolvedScope
    scope_description: str
    crypto_assets: List[CryptoAsset]
    findings: List[dict]
    policy_rules: List[dict]  # CryptoRule dumps from the effective policy
    policy_version: Optional[int]
    iana_catalog_version: Optional[int]
    scan_ids: List[str]
    # Set for meta-frameworks that run their own DB queries (e.g. PQC).
    db: Optional[AsyncIOMotorDatabase[Any]] = None


@runtime_checkable
class ComplianceFramework(Protocol):
    """Interface every framework must implement."""

    name: str
    key: ReportFramework
    version: str
    source_url: str

    @property
    def disclaimer(self) -> Optional[str]:  # shown on report cover
        ...

    @property
    def controls(self) -> List[ControlDefinition]: ...

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation: ...


def default_evaluator(
    control: ControlDefinition,
    data: EvaluationInput,
) -> ControlResult:
    """FAILED if any active matching finding, WAIVED if all matched are waived, NOT_APPLICABLE if the subject is absent, else PASSED."""
    matching = [f for f in data.findings if _finding_matches_control(f, control)]

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


def _finding_rule_ids(finding: dict) -> set:
    """All rule_ids a finding attributes itself to (lead details.rule_id plus details.matched_rules)."""
    details = finding.get("details") or {}
    ids: set = set()
    if lead_id := details.get("rule_id"):
        ids.add(lead_id)
    for m in details.get("matched_rules") or []:
        if isinstance(m, dict) and m.get("rule_id"):
            ids.add(m["rule_id"])
    return ids


def _finding_matches_control(finding: dict, control: ControlDefinition) -> bool:
    ft = finding.get("type")
    if not any(ft == (t.value if hasattr(t, "value") else t) for t in control.maps_to_finding_types):
        return False
    if control.maps_to_rule_ids:
        return bool(_finding_rule_ids(finding) & set(control.maps_to_rule_ids))
    return True


def _rules_for_control(
    control: ControlDefinition,
    policy_rules: List[dict],
) -> List[CryptoRule]:
    """Reconstruct the CryptoRule objects this control maps to from policy_rules dumps; skip absent/unparseable rules."""
    if not control.maps_to_rule_ids:
        return []
    wanted = set(control.maps_to_rule_ids)
    rules: List[CryptoRule] = []
    for raw in policy_rules:
        if raw.get("rule_id") in wanted:
            try:
                rules.append(CryptoRule.model_validate(raw))
            except Exception:  # pragma: no cover
                continue
    return rules


def _is_applicable(
    control: ControlDefinition,
    data: EvaluationInput,
) -> bool:
    """Applicable (eligible for PASSED) only when at least one crypto asset falls within a mapped rule's scope; falls back to inventory presence when the rules can't be resolved."""
    if not data.crypto_assets:
        return False
    rules = _rules_for_control(control, data.policy_rules)
    if not rules:
        # Declared rule_ids resolve to none -> possible policy drift; warn rather
        # than silently degrade to the any-asset fallback.
        if control.maps_to_rule_ids:
            logger.warning(
                "compliance: control %s maps to rule_ids %s but none resolve from the system "
                "policy; falling back to inventory presence (possible policy drift)",
                control.control_id,
                control.maps_to_rule_ids,
            )
        return True  # cannot scope to a primitive; fall back to inventory presence
    enabled_rules = [rule for rule in rules if rule.enabled]
    if not enabled_rules:
        # Every backing rule is disabled, so no finding can ever exist; PASSED
        # would be a false attestation -> NOT_APPLICABLE.
        logger.info(
            "compliance: control %s is backed only by disabled rules %s; reporting "
            "NOT_APPLICABLE rather than PASSED",
            control.control_id,
            control.maps_to_rule_ids,
        )
        return False
    return any(asset_in_rule_scope(asset, rule) for asset in data.crypto_assets for rule in enabled_rules)


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
    """Run every control and build the FrameworkEvaluation."""
    control_results: List[ControlResult] = []
    for control in framework.controls:
        if control.custom_evaluator is not None:
            result = control.custom_evaluator(data)
        else:
            result = default_evaluator(control, data)
        control_results.append(result)

    summary = build_summary(control_results)
    residuals = build_residual_risks(control_results)
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
    """Plain-string form of a ControlStatus/Severity/enum ('' for None)."""
    if status is None:
        return ""
    return status.value if hasattr(status, "value") else str(status)


def extract_finding_id(finding: Dict[str, Any]) -> str:
    """Finding ID from _id or id ('' when neither is present)."""
    return str(finding.get("_id") or finding.get("id") or "")


def _classify(matching: List[Dict[str, Any]]) -> tuple[ControlStatus, List[str]]:
    """Map matched findings to (status, evidence_ids): empty -> PASSED, any active -> FAILED, else WAIVED."""
    if not matching:
        return ControlStatus.PASSED, []
    active = [f for f in matching if not f.get("waived")]
    evidence_ids = [extract_finding_id(f) for f in matching if f.get("_id") or f.get("id")]
    if active:
        return ControlStatus.FAILED, evidence_ids
    return ControlStatus.WAIVED, evidence_ids


def _waiver_reason(f: Dict[str, Any]) -> str:
    """Best-effort waiver-reason accessor ('' when absent/None)."""
    return str(f.get("waiver_reason") or "")


def build_summary(results: List[ControlResult]) -> Dict[str, int]:
    """Count controls by status bucket."""
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


def _inputs_fingerprint(data: EvaluationInput) -> str:
    bits = "|".join(
        [
            f"policy={data.policy_version}",
            f"iana={data.iana_catalog_version}",
            f"scans={','.join(sorted(data.scan_ids))}",
        ]
    )
    return "sha256:" + hashlib.sha256(bits.encode()).hexdigest()
