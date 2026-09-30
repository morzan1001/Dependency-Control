"""Crypto policy rule evaluation, registered once per FindingType."""

from collections.abc import Sequence
from typing import Any

from app.core.constants import get_severity_value
from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType
from app.schemas.crypto_policy import CryptoRule
from app.schemas.finding_details import CryptoRuleDetails, MatchedRuleEntry
from app.services.analyzers.crypto.matcher import rule_matches
from app.services.crypto_policy.resolver import EffectivePolicy

# A crypto asset can occur in thousands of files; every finding on it would store the whole list.
MAX_FINDING_LOCATIONS = 20


def crypto_findings_for_assets(
    assets: Sequence[CryptoAsset], rules: Sequence[CryptoRule], *, scanner: str
) -> list[dict[str, Any]]:
    """One finding per asset and violated finding type, at the strictest severity matched within that type.

    All matched rules of the type are recorded in details for cross-framework attribution.
    """
    findings: list[dict[str, Any]] = []
    for asset in assets:
        by_type: dict[str, list[CryptoRule]] = {}
        for rule in rules:
            if rule_matches(asset, rule):
                by_type.setdefault(rule.finding_type, []).append(rule)
        findings.extend(_build_finding_dedup(asset, matched, scanner) for matched in by_type.values())
    return findings


def strictest_rule(rules: Sequence[CryptoRule]) -> CryptoRule:
    return max(rules, key=lambda r: get_severity_value(r.default_severity))


def matched_rule_entry(rule: CryptoRule, severity: str | None = None) -> MatchedRuleEntry:
    return MatchedRuleEntry(
        rule_id=rule.rule_id,
        rule_name=rule.name,
        policy_source=rule.source,
        severity=severity or rule.default_severity,
    )


def evaluate_rules(assets: list[CryptoAsset], policy: EffectivePolicy, *, finding_type: FindingType) -> dict[str, Any]:
    rules = [r for r in policy.active_rules if r.finding_type == finding_type]
    return {"findings": crypto_findings_for_assets(assets, rules, scanner=finding_type.value)}


def _build_finding_dedup(asset: CryptoAsset, rules: list[CryptoRule], scanner: str) -> dict[str, Any]:
    lead = strictest_rule(rules)
    ft = lead.finding_type
    component_label = f"{asset.name}" + (f" ({asset.variant})" if asset.variant else "") + f" [bom-ref:{asset.bom_ref}]"

    aggregated_references: list[str] = []
    seen_refs: set = set()
    for r in rules:
        for ref in r.references:
            if ref not in seen_refs:
                seen_refs.add(ref)
                aggregated_references.append(ref)

    return {
        # Addressable, not a nonce: findings are keyed by ``finding_id`` everywhere the API
        # exposes them, so a random id would make each run report new findings and leave every
        # crypto waiver matching nothing. One finding is emitted per asset per finding type,
        # which is exactly what this pair names.
        "id": f"CRYPTO-{ft}-{asset.bom_ref or asset.name}",
        "type": ft,
        "severity": lead.default_severity,
        "component": component_label,
        "version": asset.variant or "",
        "description": lead.description or lead.name,
        "scanners": [scanner],
        "details": CryptoRuleDetails(
            rule_id=lead.rule_id,
            rule_name=lead.name,
            policy_source=lead.source,
            matched_rules=[matched_rule_entry(r) for r in rules],
            bom_ref=asset.bom_ref,
            asset_name=asset.name,
            asset_type=asset.asset_type,
            key_size_bits=asset.key_size_bits,
            primitive=asset.primitive,
            references=aggregated_references,
            occurrence_count=len(asset.occurrence_locations),
        ).model_dump(exclude_none=True),
        "found_in": asset.occurrence_locations[:MAX_FINDING_LOCATIONS],
        "aliases": [],
    }
