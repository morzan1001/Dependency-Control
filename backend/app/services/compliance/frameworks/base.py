"""Common framework machinery: the ComplianceFramework protocol and default evaluator."""

import functools
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Protocol

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
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
from app.services.analyzers.crypto.matcher import asset_in_rule_scope, rule_matches
from app.services.crypto_policy.seeder import load_seed_file
from app.services.recommendation.common import name_some

logger = logging.getLogger(__name__)

_WITHHELD_REASON = (
    "Withheld: {evaluated} of {in_scope} {subject} in scope were read, and this verdict would "
    "have rested on finding no match among the {missing} that were not."
)
_GAPS_REASON = "Withheld: the {subject} this verdict rests on do not cover the whole scope: {gaps}."

# Gaps or assets one sentence names before it only counts the rest.
NAMES_SHOWN = 5


class _Applicability(Enum):
    APPLICABLE = auto()
    # No asset of the control's kind was found, which a truncated inventory can fake.
    NO_ASSET_IN_SCOPE = auto()
    # The policy disabled every backing rule, so no inventory can change the answer.
    RULES_DISABLED = auto()
    # The policy lacks every backing rule, so the analyzer never ran one.
    RULES_UNRESOLVED = auto()
    # An asset an enabled rule matches carries no finding, so the analysis that should flag it did not.
    UNFLAGGED = auto()
    # The CBOM states no key size for an asset a key-size minimum applies to.
    KEY_SIZE_UNKNOWN = auto()


def _withheld(
    status: ControlStatus,
    coverage: EvaluationCoverage,
    read: InputCoverage | None,
    subject: str,
) -> tuple[ControlStatus, str | None]:
    """`status` unless gaps or a cut input could hide a match; not for FAILED, which a cut input cannot invent."""
    if coverage.gaps:
        return ControlStatus.NOT_EVALUATED, _GAPS_REASON.format(
            subject=subject, gaps=name_some(coverage.gaps, NAMES_SHOWN)
        )
    if read is None or read.complete:
        return status, None
    return ControlStatus.NOT_EVALUATED, _WITHHELD_REASON.format(
        subject=subject,
        evaluated=read.evaluated,
        in_scope=read.in_scope,
        missing=read.in_scope - read.evaluated,
    )


def findings_verdict(
    status: ControlStatus,
    coverage: EvaluationCoverage,
) -> tuple[ControlStatus, str | None]:
    """`status`, or NOT_EVALUATED, for a verdict resting on the findings holding no match."""
    return _withheld(status, coverage, None, "findings")


def crypto_assets_verdict(
    status: ControlStatus,
    coverage: EvaluationCoverage,
) -> tuple[ControlStatus, str | None]:
    """`status`, or NOT_EVALUATED, for a verdict resting on the inventory holding no such asset."""
    return _withheld(status, coverage, coverage.crypto_assets, "crypto assets")


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
    override_version: int | None
    license_policy: LicensePolicySchema
    db: AsyncIOMotorDatabase[Any]
    coverage: EvaluationCoverage


class ComplianceFramework(Protocol):
    """Interface every framework must implement."""

    name: str
    key: ReportFramework
    version: str
    disclaimer: str | None

    async def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation: ...


def default_evaluator(
    control: ControlDefinition,
    data: EvaluationInput,
) -> ControlResult:
    """FAILED stands; else NOT_EVALUATED when a finding could be missing, NOT_APPLICABLE when nothing is in scope."""
    matching = [f for f in data.findings if _finding_matches_control(f, control)]
    status, evidence, status_reason = _classify(matching, data.coverage)
    if status is not ControlStatus.FAILED:
        applicability, reason = _applicability(control, data, matching)
        if reason:
            status, status_reason = ControlStatus.NOT_EVALUATED, reason
        elif not matching and applicability is _Applicability.NO_ASSET_IN_SCOPE:
            status, status_reason = crypto_assets_verdict(ControlStatus.NOT_APPLICABLE, data.coverage)
        elif not matching and applicability is _Applicability.RULES_DISABLED:
            status, status_reason = ControlStatus.NOT_APPLICABLE, None

    return ControlResult(
        control_id=control.control_id,
        title=control.title,
        description=control.description,
        status=status,
        severity=control.severity,
        evidence_finding_ids=evidence,
        evidence_asset_bom_refs=_extract_bom_refs(matching),
        waiver_reasons=_waiver_reasons(matching),
        remediation=control.remediation,
        status_reason=status_reason,
    )


def _finding_matches_control(finding: dict, control: ControlDefinition) -> bool:
    # Matching by rule_id alone survives an admin retyping the rule.
    return bool(all_rule_ids(finding.get("details")) & set(control.maps_to_rule_ids))


def _applicability(
    control: ControlDefinition,
    data: EvaluationInput,
    matching: list[dict[str, Any]],
) -> tuple[_Applicability, str | None]:
    """Only NO_ASSET_IN_SCOPE rests on the inventory, so only it is unsafe over a truncated one."""
    rules = [rule for rule in data.policy_rules if rule.rule_id in control.maps_to_rule_ids]
    if not rules:
        unresolved = (
            f"Rules {', '.join(control.maps_to_rule_ids)} are not in the effective crypto policy, "
            "so no finding can exist for this control."
        )
        return _Applicability.RULES_UNRESOLVED, None if matching else unresolved
    enabled_rules = [rule for rule in rules if rule.enabled]
    if not enabled_rules:
        logger.info(
            "compliance: control %s is backed only by disabled rules %s; reporting NOT_APPLICABLE rather than PASSED",
            control.control_id,
            control.maps_to_rule_ids,
        )
        return _Applicability.RULES_DISABLED, None
    # bom_refs repeat across projects, so only the scan tells whose finding flags an asset.
    flagged = {(f.get("scan_id"), (f.get("details") or {}).get("bom_ref")) for f in matching}
    for rule in enabled_rules:
        scoped = [asset for asset in data.crypto_assets if asset_in_rule_scope(asset, rule)]
        unflagged = sorted(
            {a.bom_ref for a in scoped if rule_matches(a, rule) and (a.scan_id, a.bom_ref) not in flagged}
        )
        if unflagged:
            return _Applicability.UNFLAGGED, (
                f"Assets {name_some(unflagged, NAMES_SHOWN)} match rule {rule.rule_id} but carry no finding, "
                "so the analysis failed or the policy changed since the scan."
            )
        sizeless = sum(asset.key_size_bits is None for asset in scoped)
        if rule.match_min_key_size_bits is not None and sizeless:
            return _Applicability.KEY_SIZE_UNKNOWN, (
                f"{sizeless} of {len(scoped)} in-scope assets carry no parseable key size, so the "
                f"{rule.match_min_key_size_bits}-bit minimum could not be checked for them."
            )
    if any(_is_subject(asset, rule) for asset in data.crypto_assets for rule in enabled_rules):
        return _Applicability.APPLICABLE, None
    return _Applicability.NO_ASSET_IN_SCOPE, None


def _is_subject(asset: CryptoAsset, rule: CryptoRule) -> bool:
    """Threshold rules judge their scope; deny-list rules judge the whole family, so a clean inventory of it passes."""
    if rule.match_min_key_size_bits is not None:
        return asset_in_rule_scope(asset, rule)
    if rule.match_primitive is not None:
        return asset.primitive == rule.match_primitive
    if rule.match_protocol_versions:
        protocol = (asset.protocol_type or "").lower()
        return bool(protocol) and any(v.lower().startswith(protocol) for v in rule.match_protocol_versions)
    return True


def _extract_bom_refs(findings: list[dict]) -> list[str]:
    refs: list[str] = []
    for f in findings:
        details = f.get("details") or {}
        if ref := details.get("bom_ref"):
            refs.append(ref)
    return sorted(set(refs))


def evaluate_framework(
    framework: ComplianceFramework,
    controls: list[ControlDefinition],
    data: EvaluationInput,
) -> FrameworkEvaluation:
    results = [(control.custom_evaluator or default_evaluator)(control, data) for control in controls]
    return build_evaluation(framework, data, results, coverage=data.coverage)


def build_evaluation(
    framework: ComplianceFramework,
    data: EvaluationInput,
    controls: list[ControlResult],
    *,
    coverage: EvaluationCoverage,
    extra_inputs: tuple[str, ...] = (),
) -> FrameworkEvaluation:
    return FrameworkEvaluation(
        framework_key=framework.key,
        framework_name=framework.name,
        framework_version=framework.version,
        generated_at=datetime.now(timezone.utc),
        scope_description=data.scope_description,
        controls=controls,
        summary=build_summary(controls),
        residual_risks=build_residual_risks(controls),
        inputs_fingerprint=_inputs_fingerprint(data, *extra_inputs),
        coverage=coverage,
    )


@dataclass
class SeedFramework:
    """A framework with one control per rule of its crypto-policy seed file."""

    key: ReportFramework
    name: str
    version: str
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
                maps_to_finding_types=[FindingType(rule.finding_type)],
            )
            for rule in load_seed_file(self.seed_file)
        ]

    async def evaluate(self, data: EvaluationInput) -> FrameworkEvaluation:
        return evaluate_framework(self, self.controls, data)


def extract_finding_id(finding: dict[str, Any]) -> str:
    """Finding ID from _id or id ('' when neither is present)."""
    return str(finding.get("_id") or finding.get("id") or "")


def _classify(
    matching: list[dict[str, Any]],
    coverage: EvaluationCoverage,
) -> tuple[ControlStatus, list[str], str | None]:
    """Map matched findings to (status, evidence_ids, status_reason): empty -> PASSED, any active
    -> FAILED, else WAIVED, with the absence-backed verdicts withheld on partial coverage."""
    if not matching:
        status, status_reason = findings_verdict(ControlStatus.PASSED, coverage)
        return status, [], status_reason
    evidence_ids = [extract_finding_id(f) for f in matching]
    if any(not f.get("waived") for f in matching):
        return ControlStatus.FAILED, evidence_ids, None
    status, status_reason = findings_verdict(ControlStatus.WAIVED, coverage)
    return status, evidence_ids, status_reason


def _waiver_reasons(findings: list[dict[str, Any]]) -> list[str]:
    return [r for f in findings if f.get("waived") and (r := f.get("waiver_reason"))]


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


def _inputs_fingerprint(data: EvaluationInput, *extra: str) -> str:
    bits = "|".join(
        [
            f"policy={data.policy_version}",
            f"override={data.override_version}",
            f"iana={data.iana_catalog_version}",
            f"scans={','.join(sorted(data.scan_ids))}",
            *extra,
        ]
    )
    return "sha256:" + hashlib.sha256(bits.encode()).hexdigest()
