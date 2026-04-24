"""
CertificateLifecycleAnalyzer

One class, seven check methods. Each check is independent and fail-soft:
a failure in one check does not block the others.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models.crypto_asset import CryptoAsset
from app.models.finding import FindingType, Severity
from app.repositories.crypto_asset import CryptoAssetRepository
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive
from app.schemas.crypto_policy import CryptoRule
from app.services.analyzers.base import Analyzer
from app.services.crypto_policy.resolver import CryptoPolicyResolver

logger = logging.getLogger(__name__)

_WEAK_HASH_NAMES = {"MD5", "MD-5", "SHA-1", "SHA1"}

_MIN_KEY_SIZES = {
    CryptoPrimitive.PKE: 2048,
    CryptoPrimitive.SIGNATURE: 2048,
}


class CertificateLifecycleAnalyzer(Analyzer):
    name = "crypto_certificate_lifecycle"

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
            repo = CryptoAssetRepository(db)
            certs = await repo.list_by_scan(
                project_id,
                scan_id,
                limit=50_000,
                asset_type=CryptoAssetType.CERTIFICATE,
            )
            algos = await repo.list_by_scan(
                project_id,
                scan_id,
                limit=50_000,
                asset_type=CryptoAssetType.ALGORITHM,
            )
            algo_by_ref = {a.bom_ref: a for a in algos}
            effective = await CryptoPolicyResolver(db).resolve(project_id)
            now = datetime.now(timezone.utc)

            findings: List[Dict[str, Any]] = []
            for cert in certs:
                for check in (
                    self._check_expired,
                    self._check_expiring,
                    self._check_not_yet_valid,
                    self._check_weak_signature,
                    self._check_weak_key,
                    self._check_self_signed,
                    self._check_validity_too_long,
                ):
                    try:
                        findings.extend(check(cert, now, effective.rules, algo_by_ref))
                    except Exception as e:
                        logger.warning(
                            "cert_lifecycle: check %s failed on %s: %s",
                            check.__name__,
                            cert.bom_ref,
                            e,
                        )
            return {"findings": findings}
        except Exception as e:
            logger.exception("cert_lifecycle analyzer failed: %s", e)
            return {"error": str(e), "findings": []}

    def _check_expired(
        self,
        cert: CryptoAsset,
        now: datetime,
        rules: List[CryptoRule],
        algo_by_ref: Dict[str, CryptoAsset],
    ) -> List[Dict[str, Any]]:
        if cert.not_valid_after is None:
            return []
        na = _ensure_aware(cert.not_valid_after)
        delta = now - na  # positive when expired
        if delta.total_seconds() <= 0:
            return []
        days_expired = int(delta.total_seconds() // 86400)
        return [
            _build(
                cert,
                type_=FindingType.CRYPTO_CERT_EXPIRED,
                severity=Severity.CRITICAL,
                description=f"Certificate expired {days_expired} days ago",
                details={"days_expired": days_expired, "not_valid_after": na.isoformat()},
            )
        ]

    def _check_expiring(
        self,
        cert: CryptoAsset,
        now: datetime,
        rules: List[CryptoRule],
        algo_by_ref: Dict[str, CryptoAsset],
    ) -> List[Dict[str, Any]]:
        if cert.not_valid_after is None:
            return []
        na = _ensure_aware(cert.not_valid_after)
        remaining = (na - now).total_seconds()
        if remaining < 0:
            return []
        days = int(remaining // 86400)
        out: List[Dict[str, Any]] = []
        for rule in rules:
            if not rule.enabled:
                continue
            if not _is_expiry_rule(rule):
                continue
            sev = _severity_from_ladder(days, rule)
            if sev is None:
                continue
            out.append(
                _build(
                    cert,
                    type_=FindingType.CRYPTO_CERT_EXPIRING_SOON,
                    severity=sev,
                    description=f"Certificate expires in {days} days",
                    details={
                        "days_until_expiry": days,
                        "threshold_matched": sev.value if hasattr(sev, "value") else sev,
                        "rule_id": rule.rule_id,
                    },
                )
            )
        return out

    def _check_not_yet_valid(
        self,
        cert: CryptoAsset,
        now: datetime,
        rules: List[CryptoRule],
        algo_by_ref: Dict[str, CryptoAsset],
    ) -> List[Dict[str, Any]]:
        if cert.not_valid_before is None:
            return []
        nb = _ensure_aware(cert.not_valid_before)
        remaining = (nb - now).total_seconds()
        if remaining <= 0:
            return []
        days = int(remaining // 86400)
        return [
            _build(
                cert,
                type_=FindingType.CRYPTO_CERT_NOT_YET_VALID,
                severity=Severity.LOW,
                description=f"Certificate not yet valid (begins in {days} days)",
                details={"days_until_valid": days, "not_valid_before": nb.isoformat()},
            )
        ]

    def _check_weak_signature(
        self,
        cert: CryptoAsset,
        now: datetime,
        rules: List[CryptoRule],
        algo_by_ref: Dict[str, CryptoAsset],
    ) -> List[Dict[str, Any]]:
        if not cert.signature_algorithm_ref:
            return []
        algo = algo_by_ref.get(cert.signature_algorithm_ref)
        if algo is None:
            return []
        prim = algo.primitive
        if isinstance(prim, str):
            try:
                prim = CryptoPrimitive(prim)
            except ValueError:
                prim = None
        is_hash = prim == CryptoPrimitive.HASH
        if is_hash and algo.name and algo.name.upper() in {n.upper() for n in _WEAK_HASH_NAMES}:
            return [
                _build(
                    cert,
                    type_=FindingType.CRYPTO_CERT_WEAK_SIGNATURE,
                    severity=Severity.HIGH,
                    description=f"Certificate signed with weak hash algorithm: {algo.name}",
                    details={
                        "algorithm_name": algo.name,
                        "related_algo_bom_ref": algo.bom_ref,
                    },
                )
            ]
        return []

    def _check_weak_key(
        self,
        cert: CryptoAsset,
        now: datetime,
        rules: List[CryptoRule],
        algo_by_ref: Dict[str, CryptoAsset],
    ) -> List[Dict[str, Any]]:
        if not cert.signature_algorithm_ref:
            return []
        algo = algo_by_ref.get(cert.signature_algorithm_ref)
        if algo is None or algo.key_size_bits is None:
            return []
        prim = algo.primitive
        if isinstance(prim, str):
            try:
                prim = CryptoPrimitive(prim)
            except ValueError:
                return []
        if prim is None:
            return []
        min_size = _MIN_KEY_SIZES.get(prim)
        if min_size is None or algo.key_size_bits >= min_size:
            return []
        return [
            _build(
                cert,
                type_=FindingType.CRYPTO_CERT_WEAK_KEY,
                severity=Severity.HIGH,
                description=(
                    f"Certificate uses weak key: {algo.name} ({algo.key_size_bits} bits < {min_size} minimum)"
                ),
                details={
                    "algorithm_name": algo.name,
                    "key_size_bits": algo.key_size_bits,
                    "min_key_size_bits": min_size,
                    "related_algo_bom_ref": algo.bom_ref,
                },
            )
        ]

    def _check_self_signed(
        self,
        cert: CryptoAsset,
        now: datetime,
        rules: List[CryptoRule],
        algo_by_ref: Dict[str, CryptoAsset],
    ) -> List[Dict[str, Any]]:
        if not cert.subject_name or not cert.issuer_name:
            return []
        if cert.subject_name.strip() != cert.issuer_name.strip():
            return []
        return [
            _build(
                cert,
                type_=FindingType.CRYPTO_CERT_SELF_SIGNED,
                severity=Severity.MEDIUM,
                description=f"Self-signed certificate: {cert.subject_name}",
                details={"subject": cert.subject_name, "issuer": cert.issuer_name},
            )
        ]

    def _check_validity_too_long(
        self,
        cert: CryptoAsset,
        now: datetime,
        rules: List[CryptoRule],
        algo_by_ref: Dict[str, CryptoAsset],
    ) -> List[Dict[str, Any]]:
        if cert.not_valid_before is None or cert.not_valid_after is None:
            return []
        nb = _ensure_aware(cert.not_valid_before)
        na = _ensure_aware(cert.not_valid_after)
        total = (na - nb).days
        if total <= 0:
            return []
        out: List[Dict[str, Any]] = []
        for rule in rules:
            if not rule.enabled:
                continue
            threshold = rule.validity_too_long_days
            if threshold is None or total <= threshold:
                continue
            sev_raw = rule.default_severity
            try:
                sev = Severity(sev_raw) if isinstance(sev_raw, str) else sev_raw
            except ValueError:
                sev = Severity.LOW
            out.append(
                _build(
                    cert,
                    type_=FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG,
                    severity=sev,
                    description=(f"Certificate validity ({total} days) exceeds policy limit of {threshold} days"),
                    details={
                        "validity_days": total,
                        "threshold": threshold,
                        "rule_id": rule.rule_id,
                    },
                )
            )
        return out


def _ensure_aware(d: datetime) -> datetime:
    return d if d.tzinfo is not None else d.replace(tzinfo=timezone.utc)


def _is_expiry_rule(rule: CryptoRule) -> bool:
    return any(
        getattr(rule, attr) is not None
        for attr in ("expiry_critical_days", "expiry_high_days", "expiry_medium_days", "expiry_low_days")
    )


def _severity_from_ladder(days: int, rule: CryptoRule) -> Optional[Severity]:
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
    details: Dict[str, Any],
) -> Dict[str, Any]:
    comp_label = f"{cert.subject_name or cert.name} [bom-ref:{cert.bom_ref}]"
    return {
        "id": str(uuid.uuid4()),
        "type": type_.value if hasattr(type_, "value") else type_,
        "severity": severity.value if hasattr(severity, "value") else severity,
        "component": comp_label,
        "version": "",
        "description": description,
        "scanners": ["crypto_certificate_lifecycle"],
        "details": {
            "bom_ref": cert.bom_ref,
            "subject_name": cert.subject_name,
            "issuer_name": cert.issuer_name,
            **details,
        },
        "found_in": list(cert.occurrence_locations),
        "aliases": [],
    }
