"""Matches the cipher suites of protocol assets against the IANA catalog, emitting one finding per weak
suite at the stricter of its catalog baseline and the enabled match_cipher_weaknesses rules it trips."""

from typing import Any

from app.core.constants import get_severity_value
from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.schemas.cbom import CryptoAssetType
from app.schemas.crypto_policy import CryptoRule
from app.schemas.finding_details import CryptoProtocolDetails
from app.services.analyzers.crypto.base import MAX_FINDING_LOCATIONS, matched_rule_entry, strictest_rule
from app.services.analyzers.crypto.catalogs.loader import (
    IANA_WEAKNESS_RULES_VERSION,
    WEAKNESS_SEVERITY,
    CipherSuiteEntry,
)
from app.services.crypto_policy.resolver import EffectivePolicy


def evaluate_protocols(
    assets: list[CryptoAsset], policy: EffectivePolicy, *, catalog: dict[str, CipherSuiteEntry]
) -> dict[str, Any]:
    by_value = {entry.value: entry for entry in catalog.values()}
    by_upper_name = {name.upper(): entry for name, entry in catalog.items()}
    amp_rules = [
        r
        for r in policy.active_rules
        if r.finding_type == FindingType.CRYPTO_WEAK_PROTOCOL and r.match_cipher_weaknesses
    ]

    findings: list[dict[str, Any]] = []
    unresolved = 0
    for proto in (a for a in assets if a.asset_type == CryptoAssetType.PROTOCOL):
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


def _build_finding(
    proto: CryptoAsset, suite_name: str, entry: CipherSuiteEntry, rules: list[CryptoRule]
) -> dict[str, Any]:
    comp_label = f"{proto.protocol_type or proto.name} {proto.version or ''} [bom-ref:{proto.bom_ref}]".strip()
    severity = max((WEAKNESS_SEVERITY[tag] for tag in entry.weaknesses), key=get_severity_value)
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
            catalog_version=IANA_WEAKNESS_RULES_VERSION,
            rule_id=lead.rule_id if lead else None,
            matched_rules=[matched_rule_entry(r) for r in rules] or None,
            occurrence_count=len(proto.occurrence_locations),
        ).model_dump(exclude_none=True),
        "found_in": proto.occurrence_locations[:MAX_FINDING_LOCATIONS],
        "aliases": [],
    }
