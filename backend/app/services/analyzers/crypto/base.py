"""
CryptoRuleAnalyzer — single class, multiple registrations (one per FindingType).

Returns `{"findings": [finding_dict, ...]}` consistent with other analyzers.
Extends the base Analyzer contract with extra kwargs project_id, scan_id, db.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional, Set

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.crypto_policy import CryptoRule
from app.services.analyzers.base import Analyzer
from app.services.analyzers.crypto.matcher import rule_matches
from app.services.crypto_policy.resolver import CryptoPolicyResolver

logger = logging.getLogger(__name__)


class CryptoRuleAnalyzer(Analyzer):
    def __init__(self, name: str, finding_types: Set[FindingType]):
        self.name = name
        self.finding_types = finding_types

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
        *,
        project_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        db: Optional[AsyncIOMotorDatabase] = None,
    ) -> Dict[str, Any]:
        if db is None or project_id is None or scan_id is None:
            return {"findings": []}

        try:
            assets = await CryptoAssetRepository(db).list_by_scan(
                project_id, scan_id, limit=50_000
            )
            effective = await CryptoPolicyResolver(db).resolve(project_id)
            relevant_finding_types = {
                ft.value if hasattr(ft, "value") else ft
                for ft in self.finding_types
            }
            rules = [
                r for r in effective.rules
                if r.enabled
                and (r.finding_type if not hasattr(r.finding_type, "value")
                     else r.finding_type.value) in relevant_finding_types
            ]
            findings: List[Dict[str, Any]] = []
            for asset in assets:
                for rule in rules:
                    if rule_matches(asset, rule):
                        findings.append(_build_finding(asset, rule))
            return {"findings": findings}
        except Exception as e:
            logger.exception("crypto analyzer %s failed: %s", self.name, e)
            return {"error": str(e), "findings": []}


def _build_finding(asset: CryptoAsset, rule: CryptoRule) -> Dict[str, Any]:
    severity = (
        rule.default_severity.value
        if hasattr(rule.default_severity, "value")
        else rule.default_severity
    )
    ft = (
        rule.finding_type.value
        if hasattr(rule.finding_type, "value")
        else rule.finding_type
    )
    src = rule.source.value if hasattr(rule.source, "value") else rule.source
    component_label = (
        f"{asset.name}"
        + (f" ({asset.variant})" if asset.variant else "")
        + f" [bom-ref:{asset.bom_ref}]"
    )
    return {
        "id": str(uuid.uuid4()),
        "type": ft,
        "severity": severity,
        "component": component_label,
        "version": asset.variant or "",
        "description": rule.description or rule.name,
        "scanners": ["crypto_rule_analyzer"],
        "details": {
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "policy_source": src,
            "bom_ref": asset.bom_ref,
            "asset_name": asset.name,
            "asset_type": (asset.asset_type.value
                           if hasattr(asset.asset_type, "value")
                           else asset.asset_type),
            "key_size_bits": asset.key_size_bits,
            "primitive": (asset.primitive.value
                          if hasattr(asset.primitive, "value")
                          else asset.primitive),
            "references": list(rule.references),
        },
        "found_in": list(asset.occurrence_locations),
        "aliases": [],
    }
