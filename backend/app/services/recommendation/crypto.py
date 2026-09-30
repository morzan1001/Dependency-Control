"""Recommendations for crypto findings, grouped by (finding_type, asset_name)."""

from collections import defaultdict
from typing import NamedTuple

from app.core.constants import max_severity
from app.models.finding import FindingType
from app.schemas.finding_details import all_rule_ids
from app.schemas.recommendation import Effort, Priority, Recommendation, RecommendationType
from app.services.recommendation.common import ModelOrDict, get_attr, sampled, severity_impact

# Findings quoted verbatim in the action block; `sampled` pairs the sample with its population.
_EVIDENCE_SAMPLED = 3

# Well-known modern replacements; falls back to generic phrasing when absent.
_MODERN_HASH = "SHA-256 or SHA-3"
_MODERN_BLOCK_CIPHER = "AES-256-GCM"
_ALGORITHM_REPLACEMENTS: dict[str, str] = {
    "MD5": _MODERN_HASH,
    "MD4": _MODERN_HASH,
    "SHA1": _MODERN_HASH,
    "SHA-1": _MODERN_HASH,
    "DES": _MODERN_BLOCK_CIPHER,
    "3DES": _MODERN_BLOCK_CIPHER,
    "RC4": f"{_MODERN_BLOCK_CIPHER} (or ChaCha20-Poly1305)",
    "RC2": _MODERN_BLOCK_CIPHER,
}


class _CryptoCard(NamedTuple):
    rec_type: RecommendationType
    effort: Effort
    # Formatted with asset, count and s (the plural suffix).
    title: str
    description: str


def _certificate_card(rec_type: RecommendationType, effort: Effort) -> _CryptoCard:
    return _CryptoCard(
        rec_type,
        effort,
        "Rotate or fix certificate: {asset}",
        "Certificate {asset} has lifecycle/integrity issues ({count} finding{s}). "
        "Rotate the certificate or correct the issuance parameters.",
    )


_ROTATE_CERTIFICATE = _certificate_card(RecommendationType.ROTATE_CERTIFICATE, Effort.LOW)

_CRYPTO_CARDS: dict[FindingType, _CryptoCard] = {
    FindingType.CRYPTO_WEAK_ALGORITHM: _CryptoCard(
        RecommendationType.REPLACE_WEAK_ALGORITHM,
        Effort.MEDIUM,
        "Replace weak algorithm: {asset}",
        "{asset} is broken or disallowed by crypto policy in {count} location{s}. "
        "Replace it with a modern primitive in the affected components.",
    ),
    FindingType.CRYPTO_WEAK_KEY: _CryptoCard(
        RecommendationType.INCREASE_KEY_SIZE,
        Effort.MEDIUM,
        "Increase key size for {asset}",
        "{asset} keys are below the policy minimum in {count} location{s}. "
        "Re-issue keys at the policy-mandated size or stronger.",
    ),
    FindingType.CRYPTO_QUANTUM_VULNERABLE: _CryptoCard(
        RecommendationType.PQC_MIGRATION,
        Effort.HIGH,
        "Plan PQC migration for {asset}",
        "{asset} is quantum-vulnerable. Use the PQC migration plan endpoint for a "
        "per-asset transition target (ML-KEM / ML-DSA / SLH-DSA per use-case).",
    ),
    FindingType.CRYPTO_WEAK_PROTOCOL: _CryptoCard(
        RecommendationType.UPGRADE_PROTOCOL,
        Effort.LOW,
        "Upgrade protocol/cipher: {asset}",
        "{asset} uses a deprecated protocol version or cipher suite ({count} finding{s}). "
        "Disable the legacy version/suite and require modern equivalents.",
    ),
    FindingType.CRYPTO_CERT_EXPIRED: _ROTATE_CERTIFICATE,
    FindingType.CRYPTO_CERT_EXPIRING_SOON: _ROTATE_CERTIFICATE,
    FindingType.CRYPTO_CERT_NOT_YET_VALID: _ROTATE_CERTIFICATE,
    FindingType.CRYPTO_CERT_SELF_SIGNED: _ROTATE_CERTIFICATE,
    FindingType.CRYPTO_CERT_VALIDITY_TOO_LONG: _ROTATE_CERTIFICATE,
    FindingType.CRYPTO_CERT_WEAK_SIGNATURE: _certificate_card(RecommendationType.REPLACE_WEAK_ALGORITHM, Effort.MEDIUM),
    FindingType.CRYPTO_CERT_WEAK_KEY: _certificate_card(RecommendationType.INCREASE_KEY_SIZE, Effort.MEDIUM),
    FindingType.CRYPTO_KEY_MANAGEMENT: _CryptoCard(
        RecommendationType.FIX_CODE_SECURITY,
        Effort.MEDIUM,
        "Fix key-management hygiene: {asset}",
        "Crypto-misuse SAST flagged {count} key-management issue{s} for {asset}. "
        "Review key generation, storage, and rotation paths.",
    ),
}

# Key-management cards are code fixes and count with SAST; every other crypto card is a crypto issue.
CRYPTO_RECOMMENDATION_TYPES = frozenset(card.rec_type for card in _CRYPTO_CARDS.values()) - {
    RecommendationType.FIX_CODE_SECURITY
}
CRYPTO_ISSUE_FINDING_TYPES = frozenset(
    finding_type.value for finding_type, card in _CRYPTO_CARDS.items() if card.rec_type in CRYPTO_RECOMMENDATION_TYPES
)

_SEVERITY_TO_PRIORITY: dict[str, Priority] = {
    "CRITICAL": Priority.CRITICAL,
    "HIGH": Priority.HIGH,
    "MEDIUM": Priority.MEDIUM,
    "LOW": Priority.LOW,
}


def process_crypto(findings: list[ModelOrDict]) -> list[Recommendation]:
    """Build remediation recommendations for crypto findings."""
    grouped: dict[tuple[str, str], list[ModelOrDict]] = defaultdict(list)
    for f in findings:
        asset_name = get_attr(f, "details", {}).get("asset_name") or get_attr(f, "component") or "unknown"
        grouped[(get_attr(f, "type"), asset_name)].append(f)
    return [
        _build_recommendation(finding_type, asset_name, group) for (finding_type, asset_name), group in grouped.items()
    ]


def _build_recommendation(finding_type: str, asset_name: str, findings: list[ModelOrDict]) -> Recommendation:
    card = _CRYPTO_CARDS[FindingType(finding_type)]
    severities = [str(get_attr(f, "severity", "UNKNOWN")) for f in findings]

    bom_refs = sorted({ref for ref in (_bom_ref(f) for f in findings) if ref})
    rule_ids = sorted({rid for f in findings for rid in all_rule_ids(get_attr(f, "details", {}))})
    descriptions = sorted({str(get_attr(f, "description", "")).strip() for f in findings if get_attr(f, "description")})
    wording = {"asset": asset_name, "count": len(findings), "s": "" if len(findings) == 1 else "s"}

    action: dict[str, object] = {
        "asset_name": asset_name,
        "finding_type": finding_type,
        "bom_refs": bom_refs,
        "rule_ids": rule_ids,
        **sampled("evidence", descriptions, _EVIDENCE_SAMPLED),
    }
    suggested = _suggested_replacement(finding_type, asset_name, findings)
    if suggested:
        action["suggested_replacement"] = suggested

    return Recommendation(
        type=card.rec_type,
        # A policy rule rated INFO or UNKNOWN still flags a breach, so it is not ranked as LOW.
        priority=_SEVERITY_TO_PRIORITY.get(max_severity(*severities), Priority.MEDIUM),
        title=card.title.format(**wording),
        description=card.description.format(**wording),
        impact=severity_impact(severities),
        affected_components=[asset_name],
        action=action,
        effort=card.effort,
    )


def _suggested_replacement(finding_type: str, asset_name: str, findings: list[ModelOrDict]) -> str | None:
    if finding_type == "crypto_weak_algorithm":
        return _ALGORITHM_REPLACEMENTS.get(asset_name.upper())
    if finding_type == "crypto_weak_key":
        # RSA/DSA below policy get bumped to the next NIST tier (3072); others defer to policy.
        for f in findings:
            details = get_attr(f, "details", {}) or {}
            if isinstance(details, dict):
                bits = details.get("key_size_bits")
                if isinstance(bits, int) and bits > 0:
                    if "RSA" in asset_name.upper() or "DSA" in asset_name.upper():
                        return f"≥3072-bit (currently {bits})"
                    return f"increase from {bits} bits per policy"
        return None
    if finding_type == "crypto_weak_protocol":
        upper = asset_name.upper()
        if "TLS" in upper:
            return "TLS 1.2 (preferably TLS 1.3) with AEAD cipher suites"
        if "SSH" in upper:
            return "SSHv2 with modern KEX/cipher set"
        return None
    if finding_type == "crypto_quantum_vulnerable":
        return "Per /api/v1/analytics/crypto/pqc-migration plan output"
    return None


def _bom_ref(finding: ModelOrDict) -> str | None:
    details = get_attr(finding, "details", {}) or {}
    if isinstance(details, dict):
        ref = details.get("bom_ref")
        return str(ref) if ref else None
    return None
