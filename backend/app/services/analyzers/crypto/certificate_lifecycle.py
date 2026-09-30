"""Certificate lifecycle checks; each check is independent and fail-soft."""

import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from app.core import ensure_utc
from app.core.constants import get_severity_value
from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoRule
from app.schemas.finding_details import CryptoCertificateDetails
from app.services.analyzers.crypto.base import MAX_FINDING_LOCATIONS, matched_rule_entry, strictest_rule
from app.services.analyzers.crypto.matcher import asset_in_rule_scope, rule_matches
from app.services.crypto_policy.resolver import EffectivePolicy

logger = logging.getLogger(__name__)


def _check_expired(
    cert: CryptoAsset, now: datetime, policy: EffectivePolicy, by_ref: dict[str, CryptoAsset]
) -> list[dict[str, Any]]:
    if cert.not_valid_after is None:
        return []
    na = ensure_utc(cert.not_valid_after)
    delta = now - na
    if delta.total_seconds() <= 0:
        return []
    severity = _policy_severity(policy, FindingType.CRYPTO_CERT_EXPIRED, Severity.CRITICAL)
    if severity is None:
        return []
    days_expired = int(delta.total_seconds() // 86400)
    return [
        _build(
            cert,
            type_=FindingType.CRYPTO_CERT_EXPIRED,
            severity=severity,
            description=f"Certificate expired {days_expired} days ago",
            details={"days_expired": days_expired, "not_valid_after": na.isoformat()},
        )
    ]


def _check_expiring(
    cert: CryptoAsset, now: datetime, policy: EffectivePolicy, by_ref: dict[str, CryptoAsset]
) -> list[dict[str, Any]]:
    if cert.not_valid_after is None:
        return []
    na = ensure_utc(cert.not_valid_after)
    remaining = (na - now).total_seconds()
    if remaining < 0:
        return []
    days = int(remaining // 86400)
    hits = [
        (severity, rule)
        for rule in policy.active_rules
        if rule.finding_type == FindingType.CRYPTO_CERT_EXPIRING_SOON
        and (severity := _severity_from_ladder(days, rule))
    ]
    if not hits:
        return []
    severity, lead = max(hits, key=lambda hit: get_severity_value(hit[0]))
    return [
        _build(
            cert,
            type_=FindingType.CRYPTO_CERT_EXPIRING_SOON,
            severity=severity,
            description=f"Certificate expires in {days} days",
            details={
                "days_until_expiry": days,
                "rule_id": lead.rule_id,
                "matched_rules": [matched_rule_entry(rule, sev) for sev, rule in hits],
            },
        )
    ]


def _check_not_yet_valid(
    cert: CryptoAsset, now: datetime, policy: EffectivePolicy, by_ref: dict[str, CryptoAsset]
) -> list[dict[str, Any]]:
    if cert.not_valid_before is None:
        return []
    nb = ensure_utc(cert.not_valid_before)
    remaining = (nb - now).total_seconds()
    if remaining <= 0:
        return []
    severity = _policy_severity(policy, FindingType.CRYPTO_CERT_NOT_YET_VALID, Severity.LOW)
    if severity is None:
        return []
    days = int(remaining // 86400)
    return [
        _build(
            cert,
            type_=FindingType.CRYPTO_CERT_NOT_YET_VALID,
            severity=severity,
            description=f"Certificate not yet valid (begins in {days} days)",
            details={"days_until_valid": days, "not_valid_before": nb.isoformat()},
        )
    ]


def _check_weak_signature(
    cert: CryptoAsset, now: datetime, policy: EffectivePolicy, by_ref: dict[str, CryptoAsset]
) -> list[dict[str, Any]]:
    algo = by_ref.get(cert.signature_algorithm_ref or "")
    if algo is None:
        return []
    # A signature algorithm such as SHA1withRSA is judged by the hash rules for its digest.
    digest = algo.model_copy(update={"primitive": CryptoPrimitive.HASH})
    matched = [
        rule
        for rule in policy.active_rules
        if rule.finding_type == FindingType.CRYPTO_WEAK_ALGORITHM
        and rule.match_primitive == CryptoPrimitive.HASH
        and rule_matches(digest, rule)
    ]
    if not matched:
        return []
    lead = strictest_rule(matched)
    return [
        _build(
            cert,
            type_=FindingType.CRYPTO_CERT_WEAK_SIGNATURE,
            severity=Severity(lead.default_severity),
            description=f"Certificate signed with weak hash algorithm: {algo.name}",
            details={"algorithm_name": algo.name, "related_algo_bom_ref": algo.bom_ref, "rule_id": lead.rule_id},
        )
    ]


def _check_weak_key(
    cert: CryptoAsset, now: datetime, policy: EffectivePolicy, by_ref: dict[str, CryptoAsset]
) -> list[dict[str, Any]]:
    # Judge the cert's own subject public key, not the CA's signing key.
    key = by_ref.get(cert.subject_public_key_ref or "")
    if key is None:
        return []
    algo = by_ref.get(key.algorithm_ref or "", key)
    size = key.key_size_bits or algo.key_size_bits
    thresholds = [
        (rule.match_min_key_size_bits, rule)
        for rule in policy.active_rules
        if rule.finding_type == FindingType.CRYPTO_WEAK_KEY
        and rule.match_min_key_size_bits is not None
        and asset_in_rule_scope(algo, rule)
    ]
    if size is None or not thresholds:
        return []
    min_size, lead = max(thresholds, key=lambda threshold: threshold[0])
    if size >= min_size:
        return []
    return [
        _build(
            cert,
            type_=FindingType.CRYPTO_CERT_WEAK_KEY,
            severity=Severity(lead.default_severity),
            description=f"Certificate uses weak key: {algo.name} ({size} bits < {min_size} minimum)",
            details={
                "algorithm_name": algo.name,
                "key_size_bits": size,
                "min_key_size_bits": min_size,
                "related_algo_bom_ref": algo.bom_ref,
                "rule_id": lead.rule_id,
            },
        )
    ]


def _check_self_signed(
    cert: CryptoAsset, now: datetime, policy: EffectivePolicy, by_ref: dict[str, CryptoAsset]
) -> list[dict[str, Any]]:
    if not cert.subject_name or not cert.issuer_name:
        return []
    if cert.subject_name.strip() != cert.issuer_name.strip():
        return []
    severity = _policy_severity(policy, FindingType.CRYPTO_CERT_SELF_SIGNED, Severity.MEDIUM)
    if severity is None:
        return []
    return [
        _build(
            cert,
            type_=FindingType.CRYPTO_CERT_SELF_SIGNED,
            severity=severity,
            description=f"Self-signed certificate: {cert.subject_name}",
            details={},
        )
    ]


def _check_validity_too_long(
    cert: CryptoAsset, now: datetime, policy: EffectivePolicy, by_ref: dict[str, CryptoAsset]
) -> list[dict[str, Any]]:
    if cert.not_valid_before is None or cert.not_valid_after is None:
        return []
    nb = ensure_utc(cert.not_valid_before)
    na = ensure_utc(cert.not_valid_after)
    total = (na - nb).days
    if total <= 0:
        return []
    exceeded = [
        rule
        for rule in policy.active_rules
        if rule.finding_type == FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG
        and rule.validity_too_long_days is not None
        and total > rule.validity_too_long_days
    ]
    if not exceeded:
        return []
    lead = strictest_rule(exceeded)
    return [
        _build(
            cert,
            type_=FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG,
            severity=Severity(lead.default_severity),
            description=f"Certificate validity ({total} days) exceeds policy limit of {lead.validity_too_long_days} days",
            details={
                "validity_days": total,
                "threshold": lead.validity_too_long_days,
                "rule_id": lead.rule_id,
                "matched_rules": [matched_rule_entry(rule) for rule in exceeded],
            },
        )
    ]


_CHECKS: tuple[
    Callable[[CryptoAsset, datetime, EffectivePolicy, dict[str, CryptoAsset]], list[dict[str, Any]]], ...
] = (
    _check_expired,
    _check_expiring,
    _check_not_yet_valid,
    _check_weak_signature,
    _check_weak_key,
    _check_self_signed,
    _check_validity_too_long,
)


def evaluate_certificates(assets: list[CryptoAsset], policy: EffectivePolicy) -> dict[str, Any]:
    # Certificates name their signature algorithm and subject key, and a key its algorithm, by bom-ref.
    by_ref = {a.bom_ref: a for a in assets}
    now = datetime.now(timezone.utc)
    findings: list[dict[str, Any]] = []
    for cert in (a for a in assets if a.asset_type == CryptoAssetType.CERTIFICATE):
        for check in _CHECKS:
            try:
                findings.extend(check(cert, now, policy, by_ref))
            except Exception as e:
                logger.warning("cert_lifecycle: check %s failed on %s: %s", check.__name__, cert.bom_ref, e)
    return {"findings": findings}


def _policy_severity(policy: EffectivePolicy, finding_type: FindingType, default: Severity) -> Severity | None:
    """Without a rule of the type the check keeps its built-in severity; rules of the type set it, or turn it off."""
    if not any(rule.finding_type == finding_type for rule in policy.rules):
        return default
    enabled = [rule for rule in policy.active_rules if rule.finding_type == finding_type]
    return Severity(strictest_rule(enabled).default_severity) if enabled else None


def _severity_from_ladder(days: int, rule: CryptoRule) -> Severity | None:
    if rule.expiry_critical_days is not None and days <= rule.expiry_critical_days:
        return Severity.CRITICAL
    if rule.expiry_high_days is not None and days <= rule.expiry_high_days:
        return Severity.HIGH
    if rule.expiry_medium_days is not None and days <= rule.expiry_medium_days:
        return Severity.MEDIUM
    if rule.expiry_low_days is not None and days <= rule.expiry_low_days:
        return Severity.LOW
    return None


def _build(
    cert: CryptoAsset,
    *,
    type_: FindingType,
    severity: Severity,
    description: str,
    details: dict[str, Any],
) -> dict[str, Any]:
    comp_label = f"{cert.subject_name or cert.name} [bom-ref:{cert.bom_ref}]"
    return {
        "id": f"CRYPTO-{type_.value}-{cert.bom_ref}",
        "type": type_.value,
        "severity": severity.value,
        "component": comp_label,
        "version": "",
        "description": description,
        "scanners": ["crypto_certificate_lifecycle"],
        "details": CryptoCertificateDetails(
            bom_ref=cert.bom_ref,
            subject_name=cert.subject_name,
            issuer_name=cert.issuer_name,
            occurrence_count=len(cert.occurrence_locations),
            **details,
        ).model_dump(exclude_none=True),
        "found_in": cert.occurrence_locations[:MAX_FINDING_LOCATIONS],
        "aliases": [],
    }
