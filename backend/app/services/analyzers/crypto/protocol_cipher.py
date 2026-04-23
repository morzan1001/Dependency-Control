"""
ProtocolCipherSuiteAnalyzer

Matches cipher-suite strings in PROTOCOL crypto assets against the IANA catalog.
Emits one finding per weak suite, plus optional amplification findings when a
project rule specifies `match_cipher_weaknesses`.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType
from app.schemas.crypto_policy import CryptoRule
from app.services.analyzers.base import Analyzer
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

    def __init__(self):
        self._catalog = load_iana_catalog()

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
                project_id,
                scan_id,
                limit=50_000,
                asset_type=CryptoAssetType.PROTOCOL,
            )
            effective = await CryptoPolicyResolver(db).resolve(project_id)
            amp_rules = [r for r in effective.rules if r.enabled and r.match_cipher_weaknesses]

            findings: List[Dict[str, Any]] = []
            for proto in assets:
                for suite_name in proto.cipher_suites:
                    key = suite_name.strip()
                    entry = self._catalog.get(key)
                    if entry is None or not entry.weaknesses:
                        continue
                    severity = _severity_from_weaknesses(entry.weaknesses)
                    findings.append(
                        _build_finding(
                            proto,
                            suite_name,
                            entry,
                            severity,
                            rule=None,
                        )
                    )
                    for rule in amp_rules:
                        if any(w in rule.match_cipher_weaknesses for w in entry.weaknesses):
                            findings.append(
                                _build_finding(
                                    proto,
                                    suite_name,
                                    entry,
                                    _rule_severity(rule),
                                    rule=rule,
                                )
                            )
            return {"findings": findings}
        except Exception as e:
            logger.exception("protocol_cipher analyzer failed: %s", e)
            return {"error": str(e), "findings": []}


def _severity_from_weaknesses(tags: List[str]) -> Severity:
    tagset = set(tags)
    for tag, sev in _WEAKNESS_SEVERITY_ORDER:
        if tag in tagset:
            return sev
    return Severity.LOW


def _rule_severity(rule: CryptoRule) -> Severity:
    sev = rule.default_severity
    if hasattr(sev, "value"):
        return sev
    try:
        return Severity(sev)
    except ValueError:
        return Severity.MEDIUM


def _build_finding(
    proto: CryptoAsset, suite_name: str, entry: CipherSuiteEntry, severity: Severity, rule: Optional[CryptoRule]
) -> Dict[str, Any]:
    comp_label = f"{proto.protocol_type or proto.name} {proto.version or ''} [bom-ref:{proto.bom_ref}]".strip()
    if rule is None:
        description = f"Cipher suite {suite_name} has weaknesses: {', '.join(entry.weaknesses)}"
    else:
        matched = [w for w in entry.weaknesses if w in rule.match_cipher_weaknesses]
        description = f"Rule '{rule.rule_id}' flagged suite {suite_name}: {', '.join(matched)}"
    return {
        "id": str(uuid.uuid4()),
        "type": FindingType.CRYPTO_WEAK_PROTOCOL.value,
        "severity": severity.value if hasattr(severity, "value") else severity,
        "component": comp_label,
        "version": proto.version or "",
        "description": description,
        "scanners": ["crypto_protocol_cipher"],
        "details": {
            "bom_ref": proto.bom_ref,
            "protocol_type": proto.protocol_type,
            "protocol_version": proto.version,
            "cipher_suite": suite_name,
            "cipher_suite_value": entry.value,
            "key_exchange": entry.key_exchange,
            "authentication": entry.authentication,
            "cipher": entry.cipher,
            "mac": entry.mac,
            "weakness_tags": list(entry.weaknesses),
            "catalog_version": CURRENT_IANA_CATALOG_VERSION,
            "rule_id": rule.rule_id if rule else None,
        },
        "found_in": list(proto.occurrence_locations),
        "aliases": [],
    }
