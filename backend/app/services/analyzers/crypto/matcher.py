"""
CryptoRule → CryptoAsset matcher.

Pure function, no I/O. AND semantics: every criterion set on the rule must
match the asset. Glob matching is case-insensitive.
"""

from fnmatch import fnmatchcase
from typing import Any, List, Optional

from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import CryptoPrimitive
from app.schemas.crypto_policy import CryptoRule

_QUANTUM_VULNERABLE_PRIMITIVES = {
    CryptoPrimitive.PKE,
    CryptoPrimitive.SIGNATURE,
    CryptoPrimitive.KEM,
}


def rule_matches(asset: CryptoAsset, rule: CryptoRule) -> bool:
    """True when the asset VIOLATES the rule: it is within the rule's subject
    scope AND fails any threshold criterion (e.g. key size below the minimum)."""
    if not asset_in_rule_scope(asset, rule):
        return False

    if rule.match_min_key_size_bits is not None:
        if asset.key_size_bits is None:
            return False
        if asset.key_size_bits >= rule.match_min_key_size_bits:
            return False

    return True


def asset_in_rule_scope(asset: CryptoAsset, rule: CryptoRule) -> bool:
    """True when the asset falls within the rule's SUBJECT scope (primitive /
    name / curve / protocol / quantum class), IGNORING threshold criteria such
    as ``match_min_key_size_bits``.

    ``rule_matches`` answers "is this asset a violation?" — a compliant RSA-4096
    key returns False there via the key-size gate. Compliance applicability
    instead needs "is the kind of crypto this rule governs present at all?", so a
    compliant key must still count. This scope-only predicate provides that.
    """
    if rule.match_primitive is not None:
        if _coerce_primitive(asset.primitive) != _coerce_primitive(rule.match_primitive):
            return False

    if rule.match_name_patterns:
        if not _name_or_variant_matches(asset, rule.match_name_patterns):
            return False

    if rule.match_curves:
        if not asset.curve or asset.curve not in rule.match_curves:
            return False

    if rule.match_protocol_versions:
        if not _protocol_version_matches(asset, rule.match_protocol_versions):
            return False

    if rule.quantum_vulnerable is True:
        # CryptoRule's validator guarantees match_name_patterns is non-empty
        # when quantum_vulnerable=True, so the pattern match was already
        # enforced above. We only need the primitive gate here.
        if _coerce_primitive(asset.primitive) not in _QUANTUM_VULNERABLE_PRIMITIVES:
            return False

    return True


def _coerce_primitive(v: Any) -> Optional[CryptoPrimitive]:
    if v is None:
        return None
    if isinstance(v, CryptoPrimitive):
        return v
    try:
        return CryptoPrimitive(v)
    except ValueError:
        return None


def _name_or_variant_matches(asset: CryptoAsset, patterns: List[str]) -> bool:
    candidates = [asset.name]
    if asset.variant:
        candidates.append(asset.variant)
    for candidate in candidates:
        c_lower = candidate.lower()
        for pat in patterns:
            pat_lower = pat.lower()
            if fnmatchcase(c_lower, pat_lower):
                return True
            if pat_lower == c_lower:
                return True
    return False


def _protocol_version_matches(asset: CryptoAsset, match_list: List[str]) -> bool:
    proto = (asset.protocol_type or "").lower()
    ver = (asset.version or "").lower()
    combined_variants = {
        f"{proto} {ver}".strip(),
        f"{proto}/{ver}".strip(),
        f"{proto}{ver}".strip(),
        ver,
    }
    for m in match_list:
        if m.lower() in combined_variants:
            return True
    return False
