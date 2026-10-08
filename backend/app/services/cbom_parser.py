"""Parse CycloneDX 1.6 ``cryptographic-asset`` components into ParsedCryptoAsset. Fail-soft: unparseable items are skipped."""

import hashlib
import json
import logging
import re
from collections import Counter
from datetime import datetime
from typing import Any

from app.schemas.cbom import CryptoAssetType, CryptoPrimitive, ParsedCryptoAsset

logger = logging.getLogger(__name__)

# Uploaded documents are untrusted; without a cap, hostile nesting raises RecursionError.
MAX_COMPONENT_NESTING_DEPTH = 100


def flatten_cyclonedx_components(components: Any, depth: int = 0) -> tuple[list[dict[str, Any]], int, int]:
    """Flatten nested components; returns (flat, depth_skipped, malformed) counting dropped entries."""
    flat: list[dict[str, Any]] = []
    depth_skipped = 0
    malformed = 0
    for comp in components if isinstance(components, list) else []:
        if not isinstance(comp, dict):
            malformed += 1
            continue
        if depth >= MAX_COMPONENT_NESTING_DEPTH:
            depth_skipped += _count_component_subtree(comp)
            continue
        flat.append(comp)
        nested, nested_skipped, nested_malformed = flatten_cyclonedx_components(comp.get("components"), depth + 1)
        flat.extend(nested)
        depth_skipped += nested_skipped
        malformed += nested_malformed
    return flat, depth_skipped, malformed


def _count_component_subtree(comp: dict[str, Any]) -> int:
    count = 0
    stack = [comp]
    while stack:
        node = stack.pop()
        count += 1
        children = node.get("components")
        if isinstance(children, list):
            stack.extend(child for child in children if isinstance(child, dict))
    return count


def parse_cbom(raw: dict[str, Any]) -> list[ParsedCryptoAsset]:
    components, _, _ = flatten_cyclonedx_components(raw.get("components"))
    return parse_crypto_components(components)


# CycloneDX 1.6 fields naming another component by bom-ref; generators such as cbomkit-theia draw those at random.
_REF_FIELDS = frozenset(
    {"bom-ref", "signatureAlgorithmRef", "subjectPublicKeyRef", "algorithmRef", "algorithms", "cryptoRefArray"}
    | {"encr", "prf", "integ", "ke", "auth"}
)


def _without_refs(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_refs(item) for key, item in value.items() if key not in _REF_FIELDS}
    if isinstance(value, list):
        return [_without_refs(item) for item in value]
    return value


def _content_ref(comp: dict[str, Any]) -> str:
    """The asset's ref from its content, so a rerun keeps its finding ids, waivers and first-seen dates."""
    return "sha-" + hashlib.sha256(json.dumps(_without_refs(comp), sort_keys=True).encode()).hexdigest()[:16]


def _remapped(raw: Any, refs: dict[str, str]) -> Any:
    """A reference to another asset of the document, by that asset's content ref when it is there."""
    return refs.get(raw, raw)


def parse_crypto_components(
    components: list[dict[str, Any]],
) -> list[ParsedCryptoAsset]:
    crypto: list[tuple[dict[str, Any], str]] = []
    seen: Counter[str] = Counter()
    for comp in components:
        if comp.get("type") == "cryptographic-asset":
            content_ref = _content_ref(comp)
            seen[content_ref] += 1
            # Identical assets stay apart; which of them takes the suffix does not matter.
            crypto.append((comp, content_ref if seen[content_ref] == 1 else f"{content_ref}-{seen[content_ref]}"))
    refs = {ref: content_ref for comp, content_ref in crypto if isinstance(ref := comp.get("bom-ref"), str)}
    out: list[ParsedCryptoAsset] = []
    for comp, content_ref in crypto:
        try:
            asset = _parse_one(comp, content_ref, refs)
            if asset is not None:
                out.append(asset)
        except Exception as e:
            logger.warning("cbom_parser: skipped component %s: %s", comp.get("bom-ref") or comp.get("name"), e)
    return out


def _parse_one(comp: dict[str, Any], content_ref: str, refs: dict[str, str]) -> ParsedCryptoAsset | None:
    name = comp.get("name")
    if not name:
        return None

    crypto_props = comp.get("cryptoProperties")
    if not crypto_props:
        logger.debug("cbom_parser: missing cryptoProperties on %s", name)
        return None

    asset_type_raw = crypto_props.get("assetType")
    try:
        asset_type = CryptoAssetType(asset_type_raw)
    except ValueError:
        logger.debug("cbom_parser: unknown assetType %r on %s, skipping", asset_type_raw, name)
        return None

    asset = ParsedCryptoAsset(
        bom_ref=content_ref,
        name=name,
        asset_type=asset_type,
        properties=component_properties(comp),
        occurrence_locations=occurrence_locations(comp),
    )

    if asset_type == CryptoAssetType.ALGORITHM:
        _populate_algorithm(asset, crypto_props.get("algorithmProperties") or {})
    elif asset_type == CryptoAssetType.CERTIFICATE:
        _populate_certificate(asset, crypto_props.get("certificateProperties") or {}, refs)
    elif asset_type == CryptoAssetType.PROTOCOL:
        _populate_protocol(asset, crypto_props.get("protocolProperties") or {})
    elif asset_type == CryptoAssetType.RELATED_CRYPTO_MATERIAL:
        material = crypto_props.get("relatedCryptoMaterialProperties") or {}
        asset.key_size_bits = _coerce_positive_int(material.get("size"))
        asset.algorithm_ref = _remapped(material.get("algorithmRef"), refs)

    _populate_evidence(asset, comp.get("evidence") or {})
    return asset


_KEY_SIZE_PROPERTY_NAMES = ("cryptography:key_size", "cryptography:keySize", "key_size", "keySize")


def _populate_algorithm(asset: ParsedCryptoAsset, props: dict[str, Any]) -> None:
    asset.primitive = _parse_primitive(props.get("primitive"))
    asset.variant = props.get("variant")
    asset.parameter_set_identifier = props.get("parameterSetIdentifier")
    asset.mode = props.get("mode")
    asset.padding = props.get("padding")
    asset.curve = props.get("curve")
    # parameterSetIdentifier is a string ("P-256", "1024"): only a positive integer is a key size, else a property.
    candidates = (props.get("parameterSetIdentifier"), *(asset.properties.get(k) for k in _KEY_SIZE_PROPERTY_NAMES))
    asset.key_size_bits = next((size for raw in candidates if (size := _coerce_positive_int(raw)) is not None), None)


def _coerce_positive_int(raw: Any) -> int | None:
    """Reject bools (Python's int(True)==1 footgun) and non-positive values."""
    if raw is None or isinstance(raw, bool):
        return None
    try:
        value = int(raw)
    except (ValueError, TypeError):
        return None
    return value if value > 0 else None


def _parse_primitive(raw: Any) -> CryptoPrimitive | None:
    if raw is None:
        return None
    try:
        return CryptoPrimitive(raw)
    except ValueError:
        return CryptoPrimitive.OTHER


def _populate_certificate(asset: ParsedCryptoAsset, props: dict[str, Any], refs: dict[str, str]) -> None:
    asset.subject_name = props.get("subjectName")
    asset.issuer_name = props.get("issuerName")
    asset.not_valid_before = _parse_iso_date(props.get("notValidBefore"))
    asset.not_valid_after = _parse_iso_date(props.get("notValidAfter"))
    asset.signature_algorithm_ref = _remapped(props.get("signatureAlgorithmRef"), refs)
    asset.subject_public_key_ref = _remapped(props.get("subjectPublicKeyRef"), refs)
    asset.certificate_format = props.get("certificateFormat")


def _populate_protocol(asset: ParsedCryptoAsset, props: dict[str, Any]) -> None:
    asset.protocol_type = props.get("type")
    asset.version = props.get("version")
    cipher_suites = props.get("cipherSuites") or []
    if isinstance(cipher_suites, list):
        for entry in cipher_suites:
            # CycloneDX 1.6 cipherSuites entries are objects; tolerate the non-spec plain-string form too.
            suite = entry if isinstance(entry, dict) else {"name": entry}
            if suite.get("name"):
                asset.cipher_suites.append(str(suite["name"]))
                asset.cipher_suite_ids.append(_cipher_suite_id(suite.get("identifiers")))


def _cipher_suite_id(identifiers: Any) -> str | None:
    """The IANA catalog's spelling: ["0xC0", "0x30"], ["0xc0,0x30"] and ["0xC030"] all give "0xC0,0x30"."""
    if not isinstance(identifiers, list):
        return None
    digits = re.sub(r"0x|[\s,]", "", ",".join(map(str, identifiers)).lower()).upper()
    return f"0x{digits[:2]},0x{digits[2:]}" if re.fullmatch(r"[0-9A-F]{4}", digits) else None


def component_properties(comp: dict[str, Any]) -> dict[str, str]:
    raw = comp.get("properties")
    return {
        str(p["name"]): str(p["value"])
        for p in (raw if isinstance(raw, list) else [])
        if isinstance(p, dict) and p.get("name") and p.get("value") not in (None, "")
    }


def occurrence_locations(comp: dict[str, Any]) -> list[str]:
    evidence = comp.get("evidence")
    occurrences = evidence.get("occurrences") if isinstance(evidence, dict) else None
    locations = (
        o.get("location") for o in (occurrences if isinstance(occurrences, list) else []) if isinstance(o, dict)
    )
    return list(dict.fromkeys(str(loc) for loc in locations if loc))


def _populate_evidence(asset: ParsedCryptoAsset, evidence: dict[str, Any]) -> None:
    detection = evidence.get("detectionContext")
    if isinstance(detection, str):
        asset.detection_context = detection
    confidence = evidence.get("confidence")
    if isinstance(confidence, (int, float)):
        asset.confidence = float(confidence)


def _parse_iso_date(raw: Any) -> datetime | None:
    if not raw or not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
