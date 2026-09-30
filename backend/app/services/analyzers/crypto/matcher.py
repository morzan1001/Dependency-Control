"""CryptoRule -> CryptoAsset matcher. AND semantics; glob matching is case-insensitive."""

import re
from fnmatch import fnmatchcase

from app.models.crypto_asset import CryptoAsset
from app.schemas.cbom import QUANTUM_VULNERABLE_PRIMITIVES
from app.schemas.crypto_policy import CryptoRule


def rule_matches(asset: CryptoAsset, rule: CryptoRule) -> bool:
    """True when the asset violates the rule: in scope AND below a threshold criterion."""
    if not asset_in_rule_scope(asset, rule):
        return False

    if rule.match_min_key_size_bits is not None:
        if asset.key_size_bits is None:
            return False
        if asset.key_size_bits >= rule.match_min_key_size_bits:
            return False

    return True


def asset_in_rule_scope(asset: CryptoAsset, rule: CryptoRule) -> bool:
    """True when the asset is within the rule's subject scope (primitive/name/curve/
    protocol/quantum class), ignoring threshold criteria; used for compliance applicability."""
    if not (rule.match_primitive or rule.match_name_patterns or rule.match_curves or rule.match_protocol_versions):
        return False

    if rule.match_primitive is not None and asset.primitive != rule.match_primitive:
        return False

    if rule.match_name_patterns and not _name_or_variant_matches(asset, rule.match_name_patterns):
        return False

    if rule.match_curves and (not asset.curve or asset.curve not in rule.match_curves):
        return False

    if rule.match_protocol_versions and not _protocol_version_matches(asset, rule.match_protocol_versions):
        return False

    # match_name_patterns is validator-guaranteed non-empty here, so only the
    # primitive gate remains.
    if rule.quantum_vulnerable is True:
        return asset.primitive in QUANTUM_VULNERABLE_PRIMITIVES

    return True


def _name_or_variant_matches(asset: CryptoAsset, patterns: list[str]) -> bool:
    candidates = [asset.name]
    if asset.variant:
        candidates.append(asset.variant)
    lowered = [pat.lower() for pat in patterns]
    for candidate in candidates:
        c_lower = candidate.lower()
        tokens = _family_tokens(c_lower)
        # Tokens hold no glob characters, so only a glob-free pattern can equal one.
        if any(pat == c_lower or pat in tokens or fnmatchcase(c_lower, pat) for pat in lowered):
            return True
    return False


# A qualifier names one family with the next part: EC-DSA is ECDSA and ML_DSA is ML-DSA, not DSA.
_QUALIFIER = re.compile(r"\b(ec|ml|slh|fn|hashml|hashslh) +")
# A post-quantum or hybrid name (X25519-MLKEM768) holds no classic family on its own.
_POST_QUANTUM_FAMILIES = ("mlkem", "mldsa", "slhdsa", "fndsa", "hashmldsa", "hashslhdsa")


def _family_tokens(name: str) -> set[str]:
    """RSA-2048 -> {rsa, 2048}, SHA1withRSA -> {sha1, sha, rsa}: name parts plus the letters before a digit run."""
    tokens = set(_QUALIFIER.sub(r"\1", " ".join(re.split(r"[^a-z0-9]+|with", name))).split())
    if any(token.startswith(_POST_QUANTUM_FAMILIES) for token in tokens):
        return set()
    return tokens | {m.group(1) for token in tokens if (m := re.match(r"([a-z]+)\d", token))}


def _protocol_version_matches(asset: CryptoAsset, match_list: list[str]) -> bool:
    proto = (asset.protocol_type or "").lower()
    ver = (asset.version or "").lower()
    combined_variants = {
        f"{proto} {ver}".strip(),
        f"{proto}/{ver}".strip(),
        f"{proto}{ver}".strip(),
        ver,
    }
    return any(m.lower() in combined_variants for m in match_list)
