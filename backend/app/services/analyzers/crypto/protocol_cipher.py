"""Matches the cipher suites of protocol assets against the IANA catalog, emitting one finding per weak
suite at the stricter of its catalog baseline and the enabled match_cipher_weaknesses rules it trips."""

import logging
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.constants import MAX_CRYPTO_ASSETS_PER_SCAN, get_severity_value
from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType
from app.schemas.crypto_policy import CryptoRule
from app.schemas.finding_details import CryptoProtocolDetails
from app.services.analyzers.base import Analyzer
from app.services.analyzers.crypto.base import matched_rule_entry, strictest_rule
from app.services.analyzers.crypto.catalogs.loader import (
    CURRENT_IANA_CATALOG_VERSION,
    CipherSuiteEntry,
    load_iana_catalog,
)
from app.services.crypto_policy.resolver import CryptoPolicyResolver

logger = logging.getLogger(__name__)

_WEAKNESS_SEVERITY_ORDER = [
    ("null-cipher", Severity.CRITICAL),
    ("null-auth", Severity.CRITICAL),
    ("export-grade", Severity.CRITICAL),
    ("anonymous", Severity.CRITICAL),
    ("weak-kex-anon", Severity.CRITICAL),
    ("weak-cipher-null", Severity.CRITICAL),
    ("weak-cipher-export", Severity.CRITICAL),
    ("weak-cipher-rc4", Severity.HIGH),
    ("weak-cipher-des", Severity.HIGH),
    ("weak-cipher-3des", Severity.HIGH),
    ("weak-mac-md5", Severity.HIGH),
    ("weak-mac-sha1", Severity.MEDIUM),
    ("weak-kex-rsa", Severity.MEDIUM),
    ("weak-kex-dh-weak", Severity.MEDIUM),
    ("no-forward-secrecy", Severity.LOW),
]


class ProtocolCipherSuiteAnalyzer(Analyzer):
    name = "crypto_protocol_cipher"

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

        catalog = await load_iana_catalog()
        by_value = {entry.value: entry for entry in catalog.values()}
        by_upper_name = {name.upper(): entry for name, entry in catalog.items()}

        try:
            assets = await CryptoAssetRepository(db).list_by_scan(
                project_id,
                scan_id,
                limit=MAX_CRYPTO_ASSETS_PER_SCAN,
                asset_type=CryptoAssetType.PROTOCOL,
            )
            effective = await CryptoPolicyResolver(db).resolve(project_id)
            amp_rules = [r for r in effective.rules if r.enabled and r.match_cipher_weaknesses]

            findings: list[dict[str, Any]] = []
            unresolved = 0
            for proto in assets:
                weak: dict[str, tuple[str, CipherSuiteEntry]] = {}
                suite_ids = proto.cipher_suite_ids or [None] * len(proto.cipher_suites)
                for suite_name, suite_id in zip(proto.cipher_suites, suite_ids, strict=False):
                    upper = suite_name.strip().upper()
                    # Java (JSSE) names every legacy suite SSL_* where IANA says TLS_*.
                    entry = by_value.get(suite_id or "") or by_upper_name.get(
                        "TLS_" + upper[4:] if upper.startswith("SSL_") else upper
                    )
                    if entry is None:
                        unresolved += 1
                    elif entry.weaknesses:
                        weak.setdefault(entry.name, (suite_name, entry))
                findings.extend(
                    _build_finding(
                        proto,
                        suite_name,
                        entry,
                        [r for r in amp_rules if set(r.match_cipher_weaknesses) & set(entry.weaknesses)],
                    )
                    for suite_name, entry in weak.values()
                )
            return {"findings": findings, "unresolved_cipher_suites": unresolved}
        except Exception as e:
            logger.exception("protocol_cipher analyzer failed: %s", e)
            return {"error": str(e), "findings": []}


def _severity_from_weaknesses(tags: list[str]) -> Severity:
    tagset = set(tags)
    for tag, sev in _WEAKNESS_SEVERITY_ORDER:
        if tag in tagset:
            return sev
    return Severity.LOW


def _build_finding(
    proto: CryptoAsset, suite_name: str, entry: CipherSuiteEntry, rules: list[CryptoRule]
) -> dict[str, Any]:
    comp_label = f"{proto.protocol_type or proto.name} {proto.version or ''} [bom-ref:{proto.bom_ref}]".strip()
    severity = _severity_from_weaknesses(entry.weaknesses)
    description = f"Cipher suite {suite_name} has weaknesses: {', '.join(entry.weaknesses)}"
    lead = strictest_rule(rules) if rules else None
    if lead is not None:
        severity = max(severity, Severity(lead.default_severity), key=get_severity_value)
        description += f"; flagged by {', '.join(r.rule_id for r in rules)}"
    return {
        "id": f"CRYPTO-{FindingType.CRYPTO_WEAK_PROTOCOL.value}-{proto.bom_ref}-{entry.name}",
        "type": FindingType.CRYPTO_WEAK_PROTOCOL.value,
        "severity": severity.value,
        "component": comp_label,
        "version": proto.version or "",
        "description": description,
        "scanners": ["crypto_protocol_cipher"],
        "details": CryptoProtocolDetails(
            bom_ref=proto.bom_ref,
            protocol_type=proto.protocol_type,
            protocol_version=proto.version,
            cipher_suite=suite_name,
            cipher_suite_value=entry.value,
            key_exchange=entry.key_exchange,
            authentication=entry.authentication,
            cipher=entry.cipher,
            mac=entry.mac,
            weakness_tags=list(entry.weaknesses),
            catalog_version=CURRENT_IANA_CATALOG_VERSION,
            rule_id=lead.rule_id if lead else None,
            matched_rules=[matched_rule_entry(r) for r in rules] or None,
        ).model_dump(exclude_none=True),
        "found_in": list(proto.occurrence_locations),
        "aliases": [],
    }
