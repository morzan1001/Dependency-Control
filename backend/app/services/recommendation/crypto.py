"""Recommendations for cryptographic findings.

The crypto analyzers emit one of five FindingType values; each maps to
a different remediation pattern, which in turn maps to one of the
crypto RecommendationType values defined in app.schemas.recommendation.

Findings are grouped by `(finding_type, asset_name)` so multiple
occurrences of the same weakness on the same asset collapse into a
single recommendation instead of flooding the dashboard.
"""

from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from app.schemas.recommendation import Effort, Priority, Recommendation, RecommendationType
from app.services.recommendation.common import get_attr, ModelOrDict

CRYPTO_FINDING_TYPES = {
    "crypto_weak_algorithm",
    "crypto_weak_key",
    "crypto_quantum_vulnerable",
    "crypto_weak_protocol",
    "crypto_protocol_cipher",
    "crypto_certificate_lifecycle",
    "crypto_cert_expired",
    "crypto_cert_expiring_soon",
    "crypto_cert_not_yet_valid",
    "crypto_cert_weak_signature",
    "crypto_cert_weak_key",
    "crypto_cert_self_signed",
    "crypto_cert_validity_too_long",
    "crypto_key_management",
}

# A few well-known modern replacements; the recommendation falls back
# to a generic phrasing when the source family isn't in this map.
_MODERN_HASH = "SHA-256 or SHA-3"
_MODERN_BLOCK_CIPHER = "AES-256-GCM"
_ALGORITHM_REPLACEMENTS: Dict[str, str] = {
    "MD5": _MODERN_HASH,
    "MD4": _MODERN_HASH,
    "SHA1": _MODERN_HASH,
    "SHA-1": _MODERN_HASH,
    "DES": _MODERN_BLOCK_CIPHER,
    "3DES": _MODERN_BLOCK_CIPHER,
    "RC4": f"{_MODERN_BLOCK_CIPHER} (or ChaCha20-Poly1305)",
    "RC2": _MODERN_BLOCK_CIPHER,
}

_TYPE_TO_RECTYPE: Dict[str, RecommendationType] = {
    "crypto_weak_algorithm": RecommendationType.REPLACE_WEAK_ALGORITHM,
    "crypto_weak_key": RecommendationType.INCREASE_KEY_SIZE,
    "crypto_quantum_vulnerable": RecommendationType.PQC_MIGRATION,
    "crypto_weak_protocol": RecommendationType.UPGRADE_PROTOCOL,
    "crypto_protocol_cipher": RecommendationType.REPLACE_WEAK_CIPHER_SUITE,
    "crypto_certificate_lifecycle": RecommendationType.ROTATE_CERTIFICATE,
    "crypto_cert_expired": RecommendationType.ROTATE_CERTIFICATE,
    "crypto_cert_expiring_soon": RecommendationType.ROTATE_CERTIFICATE,
    "crypto_cert_not_yet_valid": RecommendationType.ROTATE_CERTIFICATE,
    "crypto_cert_weak_signature": RecommendationType.REPLACE_WEAK_ALGORITHM,
    "crypto_cert_weak_key": RecommendationType.INCREASE_KEY_SIZE,
    "crypto_cert_self_signed": RecommendationType.ROTATE_CERTIFICATE,
    "crypto_cert_validity_too_long": RecommendationType.ROTATE_CERTIFICATE,
    "crypto_key_management": RecommendationType.FIX_CODE_SECURITY,
}

_SEVERITY_TO_PRIORITY: Dict[str, Priority] = {
    "CRITICAL": Priority.CRITICAL,
    "HIGH": Priority.HIGH,
    "MEDIUM": Priority.MEDIUM,
    "LOW": Priority.LOW,
}

# Most crypto fixes need code/config + redeployment, so default to MEDIUM.
# Cert rotation is operational (low effort), PQC is a multi-quarter project.
_TYPE_TO_EFFORT: Dict[str, str] = {
    "crypto_weak_algorithm": Effort.MEDIUM,
    "crypto_weak_key": Effort.MEDIUM,
    "crypto_quantum_vulnerable": Effort.HIGH,
    "crypto_weak_protocol": Effort.LOW,
    "crypto_protocol_cipher": Effort.LOW,
    "crypto_certificate_lifecycle": Effort.LOW,
    "crypto_cert_expired": Effort.LOW,
    "crypto_cert_expiring_soon": Effort.LOW,
    "crypto_cert_not_yet_valid": Effort.LOW,
    "crypto_cert_weak_signature": Effort.MEDIUM,
    "crypto_cert_weak_key": Effort.MEDIUM,
    "crypto_cert_self_signed": Effort.LOW,
    "crypto_cert_validity_too_long": Effort.LOW,
    "crypto_key_management": Effort.MEDIUM,
}


def process_crypto(findings: List[ModelOrDict]) -> List[Recommendation]:
    """Build remediation recommendations for crypto findings."""
    if not findings:
        return []

    grouped: Dict[Tuple[str, str], List[ModelOrDict]] = defaultdict(list)
    for f in findings:
        finding_type = get_attr(f, "type", "")
        if finding_type not in CRYPTO_FINDING_TYPES:
            continue
        details = get_attr(f, "details", {}) or {}
        asset_name = (
            (details.get("asset_name") if isinstance(details, dict) else None)
            or get_attr(f, "component", "unknown")
            or "unknown"
        )
        grouped[(finding_type, asset_name)].append(f)

    out: List[Recommendation] = []
    for (finding_type, asset_name), group in grouped.items():
        rec = _build_recommendation(finding_type, asset_name, group)
        if rec is not None:
            out.append(rec)
    return out


def _build_recommendation(
    finding_type: str,
    asset_name: str,
    findings: List[ModelOrDict],
) -> Optional[Recommendation]:
    rec_type = _TYPE_TO_RECTYPE.get(finding_type)
    if rec_type is None:
        return None

    severities = [str(get_attr(f, "severity", "UNKNOWN")) for f in findings]
    top_severity = _highest_severity(severities)
    priority = _SEVERITY_TO_PRIORITY.get(top_severity, Priority.MEDIUM)
    effort = _TYPE_TO_EFFORT.get(finding_type, Effort.MEDIUM)

    bom_refs = sorted({ref for ref in (_bom_ref(f) for f in findings) if ref})
    rule_ids = sorted({rid for rid in (_rule_id(f) for f in findings) if rid})
    descriptions = sorted({str(get_attr(f, "description", "")).strip() for f in findings if get_attr(f, "description")})

    impact: Dict[str, int] = {
        "critical": severities.count("CRITICAL"),
        "high": severities.count("HIGH"),
        "medium": severities.count("MEDIUM"),
        "low": severities.count("LOW"),
        "total": len(findings),
    }

    title, description = _title_and_description(finding_type, asset_name, findings)

    action: Dict[str, object] = {
        "asset_name": asset_name,
        "finding_type": finding_type,
        "bom_refs": bom_refs,
        "rule_ids": rule_ids,
        "evidence": descriptions[:3],
    }
    suggested = _suggested_replacement(finding_type, asset_name, findings)
    if suggested:
        action["suggested_replacement"] = suggested

    return Recommendation(
        type=rec_type,
        priority=priority,
        title=title,
        description=description,
        impact=impact,
        affected_components=[asset_name],
        action=action,
        effort=effort,
    )


def _title_and_description(finding_type: str, asset_name: str, findings: List[ModelOrDict]) -> Tuple[str, str]:
    count = len(findings)
    plural = "s" if count != 1 else ""
    if finding_type == "crypto_weak_algorithm":
        return (
            f"Replace weak algorithm: {asset_name}",
            f"{asset_name} is flagged by {count} crypto policy rule{plural} as broken or disallowed. "
            f"Replace it with a modern primitive in the affected components.",
        )
    if finding_type == "crypto_weak_key":
        return (
            f"Increase key size for {asset_name}",
            f"{asset_name} keys are below the policy minimum in {count} location{plural}. "
            f"Re-issue keys at the policy-mandated size or stronger.",
        )
    if finding_type == "crypto_quantum_vulnerable":
        return (
            f"Plan PQC migration for {asset_name}",
            f"{asset_name} is quantum-vulnerable. Use the PQC migration plan endpoint for a "
            f"per-asset transition target (ML-KEM / ML-DSA / SLH-DSA per use-case).",
        )
    if finding_type in ("crypto_weak_protocol", "crypto_protocol_cipher"):
        return (
            f"Upgrade protocol/cipher: {asset_name}",
            f"{asset_name} uses a deprecated protocol version or cipher suite ({count} finding{plural}). "
            f"Disable the legacy version/suite and require modern equivalents.",
        )
    if finding_type.startswith("crypto_cert_"):
        return (
            f"Rotate or fix certificate: {asset_name}",
            f"Certificate {asset_name} has lifecycle/integrity issues ({count} finding{plural}). "
            f"Rotate the certificate or correct the issuance parameters.",
        )
    if finding_type == "crypto_certificate_lifecycle":
        return (
            f"Rotate certificate: {asset_name}",
            f"{asset_name} hit a certificate lifecycle threshold in {count} finding{plural}.",
        )
    if finding_type == "crypto_key_management":
        return (
            f"Fix key-management hygiene: {asset_name}",
            f"Crypto-misuse SAST flagged {count} key-management issue{plural} for {asset_name}. "
            f"Review key generation, storage, and rotation paths.",
        )
    return (
        f"Crypto issue: {asset_name}",
        f"{count} crypto finding{plural} on {asset_name}",
    )


def _suggested_replacement(finding_type: str, asset_name: str, findings: List[ModelOrDict]) -> Optional[str]:
    if finding_type == "crypto_weak_algorithm":
        return _ALGORITHM_REPLACEMENTS.get(asset_name.upper())
    if finding_type == "crypto_weak_key":
        # Pick the first non-null key_size_bits and recommend a doubling
        # bumped to the next NIST-friendly tier. For RSA <2048 -> 3072,
        # otherwise leave to policy.
        for f in findings:
            details = get_attr(f, "details", {}) or {}
            if isinstance(details, dict):
                bits = details.get("key_size_bits")
                if isinstance(bits, int) and bits > 0:
                    if "RSA" in asset_name.upper() or "DSA" in asset_name.upper():
                        return f"≥3072-bit (currently {bits})"
                    return f"increase from {bits} bits per policy"
        return None
    if finding_type == "crypto_weak_protocol" or finding_type == "crypto_protocol_cipher":
        upper = asset_name.upper()
        if "TLS" in upper:
            return "TLS 1.2 (preferably TLS 1.3) with AEAD cipher suites"
        if "SSH" in upper:
            return "SSHv2 with modern KEX/cipher set"
        return None
    if finding_type == "crypto_quantum_vulnerable":
        return "Per /api/v1/analytics/crypto/pqc-migration plan output"
    return None


def _highest_severity(severities: List[str]) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    for s in order:
        if s in severities:
            return s
    return "UNKNOWN"


def _bom_ref(finding: ModelOrDict) -> Optional[str]:
    details = get_attr(finding, "details", {}) or {}
    if isinstance(details, dict):
        ref = details.get("bom_ref")
        return str(ref) if ref else None
    return None


def _rule_id(finding: ModelOrDict) -> Optional[str]:
    details = get_attr(finding, "details", {}) or {}
    if isinstance(details, dict):
        rid = details.get("rule_id")
        return str(rid) if rid else None
    return None
