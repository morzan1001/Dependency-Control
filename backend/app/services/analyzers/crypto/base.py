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
            assets = await CryptoAssetRepository(db).list_by_scan(project_id, scan_id, limit=50_000)
            effective = await CryptoPolicyResolver(db).resolve(project_id)
            relevant_finding_types = {ft.value if hasattr(ft, "value") else ft for ft in self.finding_types}
            rules = [
                r
                for r in effective.rules
                if r.enabled
                and (r.finding_type if not hasattr(r.finding_type, "value") else r.finding_type.value)
                in relevant_finding_types
            ]
            findings: List[Dict[str, Any]] = []
            for asset in assets:
                matched_rules = [r for r in rules if rule_matches(asset, r)]
                if not matched_rules:
                    continue
                # Multiple frameworks may match the same asset (e.g. SHA-1
                # is flagged by both BSI TR-02102 and NIST SP 800-131A).
                # Emit one finding per (asset, finding_type), keep the
                # strictest severity, and record every matched rule in
                # details so the audit trail and compliance evaluators
                # still see the cross-framework agreement.
                findings.append(_build_finding_dedup(asset, matched_rules))
            return {"findings": findings}
        except Exception as e:
            logger.exception("crypto analyzer %s failed: %s", self.name, e)
            return {"error": str(e), "findings": []}


_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "UNKNOWN": 0}


def _build_finding(asset: CryptoAsset, rule: CryptoRule) -> Dict[str, Any]:
    return _build_finding_dedup(asset, [rule])


def _build_finding_dedup(asset: CryptoAsset, rules: List[CryptoRule]) -> Dict[str, Any]:
    """Build one finding for an asset that matched ``rules``.

    The lead rule (the one whose attributes are projected onto the
    top-level Finding fields) is the strictest by default_severity.
    Every other matched rule still appears under
    ``details.matched_rules`` so compliance evaluators and audit views
    can attribute the finding to multiple frameworks without inflating
    findings_count or severity_mix counts.
    """
    lead = max(rules, key=lambda r: _SEVERITY_RANK.get(_severity_str(r.default_severity), 0))
    severity = _severity_str(lead.default_severity)
    ft = lead.finding_type.value if hasattr(lead.finding_type, "value") else lead.finding_type
    component_label = f"{asset.name}" + (f" ({asset.variant})" if asset.variant else "") + f" [bom-ref:{asset.bom_ref}]"

    matched_rules_detail = [
        {
            "rule_id": r.rule_id,
            "rule_name": r.name,
            "policy_source": r.source.value if hasattr(r.source, "value") else r.source,
            "severity": _severity_str(r.default_severity),
        }
        for r in rules
    ]
    aggregated_references: List[str] = []
    seen_refs: set = set()
    for r in rules:
        for ref in r.references:
            if ref not in seen_refs:
                seen_refs.add(ref)
                aggregated_references.append(ref)

    return {
        "id": str(uuid.uuid4()),
        "type": ft,
        "severity": severity,
        "component": component_label,
        "version": asset.variant or "",
        "description": lead.description or lead.name,
        "scanners": ["crypto_rule_analyzer"],
        "details": {
            "rule_id": lead.rule_id,
            "rule_name": lead.name,
            "policy_source": lead.source.value if hasattr(lead.source, "value") else lead.source,
            "matched_rules": matched_rules_detail,
            "bom_ref": asset.bom_ref,
            "asset_name": asset.name,
            "asset_type": (asset.asset_type.value if hasattr(asset.asset_type, "value") else asset.asset_type),
            "key_size_bits": asset.key_size_bits,
            "primitive": (
                asset.primitive.value
                if asset.primitive is not None and hasattr(asset.primitive, "value")
                else asset.primitive
            ),
            "references": aggregated_references,
        },
        "found_in": list(asset.occurrence_locations),
        "aliases": [],
    }


def _severity_str(s: Any) -> str:
    return s.value if hasattr(s, "value") else str(s)
