"""Common framework machinery: the ComplianceFramework protocol and default evaluator."""

import functools
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Protocol, runtime_checkable

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_asset import CryptoAsset
from app.models.finding import Severity
from app.schemas.compliance import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    EvaluationCoverage,
    FrameworkEvaluation,
    InputCoverage,
    ReportFramework,
    ResidualRisk,
)
from app.schemas.crypto_policy import CryptoRule
from app.schemas.finding_details import all_rule_ids
from app.schemas.project import LicensePolicySchema
from app.services.analytics.scopes import ResolvedScope
from app.services.analyzers.crypto.matcher import asset_in_rule_scope
from app.services.crypto_policy.seeder import load_seed_file

logger = logging.getLogger(__name__)

_WITHHELD_REASON = (
    "Withheld: {evaluated} of {in_scope} {subject} in scope were read, and this verdict would "
    "have rested on finding no match among the {missing} that were not."
)


class _Applicability(Enum):
    APPLICABLE = auto()
    # No asset of the control's kind was found, which a truncated inventory can fake.
    NO_ASSET_IN_SCOPE = auto()
    # The policy disabled every backing rule, so no inventory can change the answer.
    RULES_DISABLED = auto()
    # The policy lacks every backing rule, so the analyzer never ran one.
    RULES_UNRESOLVED = auto()


def _withheld(
    status: ControlStatus,
    coverage: InputCoverage | None,
    subject: str,
) -> tuple[ControlStatus, str | None]:
    """`status`, or NOT_EVALUATED and why, when the input it rests on did not cover the scope.
    Call it only for a status whose evidence is that input holding no match: FAILED never
    qualifies, because a cut input under-reports a violation but cannot invent one."""
    if coverage is None or coverage.complete:
        return status, None
    return ControlStatus.NOT_EVALUATED, _WITHHELD_REASON.format(
        subject=subject,
        evaluated=coverage.evaluated,
        in_scope=coverage.in_scope,
        missing=coverage.in_scope - coverage.evaluated,
    )


def findings_verdict(
    status: ControlStatus,
    coverage: EvaluationCoverage | None,
) -> tuple[ControlStatus, str | None]:
    """`status`, or NOT_EVALUATED, for a verdict resting on the findings holding no match."""
    return _withheld(status, coverage.findings if coverage else None, "findings")


def crypto_assets_verdict(
    status: ControlStatus,
    coverage: EvaluationCoverage | None,
) -> tuple[ControlStatus, str | None]:
    """`status`, or NOT_EVALUATED, for a verdict resting on the inventory holding no such asset."""
    return _withheld(status, coverage.crypto_assets if coverage else None, "crypto assets")


@dataclass
class EvaluationInput:
    resolved: ResolvedScope
    scope_description: str
    crypto_assets: list[CryptoAsset]
    findings: list[dict]
    policy_rules: list[CryptoRule]
    policy_version: int | None
    iana_catalog_version: int | None
    scan_ids: list[str]
    override_version: int | None = None
    license_policy: LicensePolicySchema = field(default_factory=LicensePolicySchema)
    # Set for meta-frameworks that run their own DB queries (e.g. PQC).
    db: AsyncIOMotorDatabase[Any] | None = None
    # What `findings` covers of the scope. None where the caller assembled the input itself and
    # therefore already knows.
    coverage: EvaluationCoverage | None = None


@runtime_checkable
class ComplianceFramework(Protocol):
    """Interface every framework must implement."""

    name: str
    key: ReportFramework
    version: str
    source_url: str

    @property
    def disclaimer(self) -> str | None:  # shown on report cover
        ...

    @property
    def controls(self) -> list[ControlDefinition]: ...

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation: ...


def default_evaluator(
    control: ControlDefinition,
    data: EvaluationInput,
) -> ControlResult:
    """FAILED if any active matching finding, WAIVED if all matched are waived, NOT_APPLICABLE if the subject is absent, else PASSED."""
    matching = [f for f in data.findings if _finding_matches_control(f, control)]

    waived_findings = [f for f in matching if f.get("waived")]
    active_findings = [f for f in matching if not f.get("waived")]

    status_reason: str | None = None
    if active_findings:
        status = ControlStatus.FAILED
    elif waived_findings:
        status, status_reason = findings_verdict(ControlStatus.WAIVED, data.coverage)
    else:
        applicability = _applicability(control, data)
        if applicability is _Applicability.APPLICABLE:
            status, status_reason = findings_verdict(ControlStatus.PASSED, data.coverage)
        elif applicability is _Applicability.NO_ASSET_IN_SCOPE:
            status, status_reason = crypto_assets_verdict(ControlStatus.NOT_APPLICABLE, data.coverage)
        elif applicability is _Applicability.RULES_UNRESOLVED:
            status = ControlStatus.NOT_EVALUATED
            status_reason = (
                f"Rules {', '.join(control.maps_to_rule_ids)} are not in the effective crypto policy, "
                "so no finding can exist for this control."
            )
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
        status_reason=status_reason,
    )


def _finding_matches_control(finding: dict, control: ControlDefinition) -> bool:
    # Matching by rule_id alone survives an admin retyping the rule.
    return bool(all_rule_ids(finding.get("details")) & set(control.maps_to_rule_ids))


def _applicability(
    control: ControlDefinition,
    data: EvaluationInput,
) -> "_Applicability":
    """Applicable (eligible for PASSED) only when at least one crypto asset falls within an enabled mapped rule's scope.

    The inapplicable answers are told apart because only NO_ASSET_IN_SCOPE is read off the
    inventory, and only that one is unsafe to state over a truncated inventory.
    """
    rules = [rule for rule in data.policy_rules if rule.rule_id in control.maps_to_rule_ids]
    if not rules:
        return _Applicability.RULES_UNRESOLVED
    enabled_rules = [rule for rule in rules if rule.enabled]
    if not enabled_rules:
        # Every backing rule is disabled, so no finding can ever exist; PASSED
        # would be a false attestation -> NOT_APPLICABLE.
        logger.info(
            "compliance: control %s is backed only by disabled rules %s; reporting NOT_APPLICABLE rather than PASSED",
            control.control_id,
            control.maps_to_rule_ids,
        )
        return _Applicability.RULES_DISABLED
    in_scope = any(asset_in_rule_scope(asset, rule) for asset in data.crypto_assets for rule in enabled_rules)
    return _Applicability.APPLICABLE if in_scope else _Applicability.NO_ASSET_IN_SCOPE


def _extract_bom_refs(findings: list[dict]) -> list[str]:
    refs: list[str] = []
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
    control_results: list[ControlResult] = []
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


@dataclass
class SeedFramework:
    """A framework with one control per rule of its crypto-policy seed file."""

    key: ReportFramework
    name: str
    version: str
    source_url: str
    seed_file: str
    control_id_prefix: str
    disclaimer: str | None = None

    @functools.cached_property
    def controls(self) -> list[ControlDefinition]:
        return [
            ControlDefinition(
                control_id=f"{self.control_id_prefix}-{rule.rule_id}",
                title=rule.name,
                description=rule.description.strip() or rule.name,
                severity=Severity(rule.default_severity),
                remediation=rule.description.strip(),
                maps_to_rule_ids=[rule.rule_id],
            )
            for rule in load_seed_file(self.seed_file)
        ]

    def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, data)


def extract_finding_id(finding: dict[str, Any]) -> str:
    """Finding ID from _id or id ('' when neither is present)."""
    return str(finding.get("_id") or finding.get("id") or "")


def _classify(
    matching: list[dict[str, Any]],
    coverage: EvaluationCoverage | None,
) -> tuple[ControlStatus, list[str], str | None]:
    """Map matched findings to (status, evidence_ids, status_reason): empty -> PASSED, any active
    -> FAILED, else WAIVED, with the absence-backed verdicts withheld on partial coverage."""
    if not matching:
        status, status_reason = findings_verdict(ControlStatus.PASSED, coverage)
        return status, [], status_reason
    active = [f for f in matching if not f.get("waived")]
    evidence_ids = [extract_finding_id(f) for f in matching if f.get("_id") or f.get("id")]
    if active:
        return ControlStatus.FAILED, evidence_ids, None
    status, status_reason = findings_verdict(ControlStatus.WAIVED, coverage)
    return status, evidence_ids, status_reason


def _waiver_reason(f: dict[str, Any]) -> str:
    """Best-effort waiver-reason accessor ('' when absent/None)."""
    return str(f.get("waiver_reason") or "")


def build_summary(results: list[ControlResult]) -> dict[str, int]:
    """Count controls by status bucket."""
    counts = {
        "passed": 0,
        "failed": 0,
        "waived": 0,
        "not_applicable": 0,
        "not_evaluated": 0,
        "total": len(results),
    }
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def build_residual_risks(results: list[ControlResult]) -> list[ResidualRisk]:
    """Convert every FAILED ControlResult into a ResidualRisk entry."""
    return [
        ResidualRisk(
            control_id=r.control_id,
            title=r.title,
            severity=r.severity,
            description=r.description,
        )
        for r in results
        if r.status == ControlStatus.FAILED
    ]


def _inputs_fingerprint(data: EvaluationInput) -> str:
    bits = "|".join(
        [
            f"policy={data.policy_version}",
            f"override={data.override_version}",
            f"iana={data.iana_catalog_version}",
            f"scans={','.join(sorted(data.scan_ids))}",
        ]
    )
    return "sha256:" + hashlib.sha256(bits.encode()).hexdigest()
