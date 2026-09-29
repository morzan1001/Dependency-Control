"""Crypto policy rule analyzer, registered once per FindingType."""

import asyncio
import logging
from collections.abc import Sequence
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import MAX_CRYPTO_ASSETS_PER_SCAN, get_severity_value
from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.crypto_policy import CryptoRule
from app.schemas.finding_details import CryptoRuleDetails, MatchedRuleEntry
from app.services.analyzers.base import Analyzer
from app.services.analyzers.crypto.matcher import rule_matches
from app.services.crypto_policy.resolver import CryptoPolicyResolver

logger = logging.getLogger(__name__)


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


class CryptoRuleAnalyzer(Analyzer):
    def __init__(self, name: str, finding_types: set[FindingType]):
        self.name = name
        self.finding_types = finding_types

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        parsed_components: list[dict[str, Any]] | None = None,
        *,
        project_id: str | None = None,
        scan_id: str | None = None,
        db: AsyncIOMotorDatabase | None = None,
    ) -> dict[str, Any]:
        if db is None or project_id is None or scan_id is None:
            return {"findings": []}

        try:
            assets = await CryptoAssetRepository(db).list_by_scan(project_id, scan_id, limit=MAX_CRYPTO_ASSETS_PER_SCAN)
            effective = await CryptoPolicyResolver(db).resolve(project_id)
            rules = [r for r in effective.rules if r.enabled and r.finding_type in self.finding_types]
            # assets x rules matching; off the event loop every tenant shares.
            findings = await asyncio.to_thread(crypto_findings_for_assets, assets, rules, scanner=self.name)
            return {"findings": findings}
        except Exception as e:
            logger.exception("crypto analyzer %s failed: %s", self.name, e)
            return {"error": str(e), "findings": []}


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
        ).model_dump(exclude_none=True),
        "found_in": list(asset.occurrence_locations),
        "aliases": [],
    }
