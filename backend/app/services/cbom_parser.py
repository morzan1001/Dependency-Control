"""
CBOM Parser

Parses CycloneDX 1.6 `cryptographic-asset` components into ParsedCryptoAsset.

Two entry points:
- parse_cbom(raw_payload): full CBOM payload (used by /ingest/cbom endpoint)
- parse_crypto_components(components): component list only (used by sbom_parser
  when it detects cryptographic-asset types inside a regular SBOM)

Fail-soft: unparseable items are skipped and counted, never crash the caller.
"""

import hashlib
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.schemas.cbom import (
    CryptoAssetType,
    CryptoPrimitive,
    ParsedCBOM,
    ParsedCryptoAsset,
)

logger = logging.getLogger(__name__)


def parse_cbom(raw: Dict[str, Any]) -> ParsedCBOM:
    components = raw.get("components") or []
    tool_meta = (raw.get("metadata") or {}).get("tools") or []
    tool_name = _tool_name_from_metadata(tool_meta)
    tool_version = _tool_version_from_metadata(tool_meta)

    total = sum(1 for c in components if c.get("type") == "cryptographic-asset")
    assets = parse_crypto_components(components)

    return ParsedCBOM(
        format_version=raw.get("specVersion"),
        tool_name=tool_name,
        tool_version=tool_version,
        created_at=(raw.get("metadata") or {}).get("timestamp"),
        assets=assets,
        total_components=total,
        parsed_components=len(assets),
        skipped_components=total - len(assets),
    )


def _tool_name_from_metadata(tools: Any) -> Optional[str]:
    if isinstance(tools, dict):
        comps = tools.get("components") or []
        if comps:
            value = comps[0].get("name")
            return str(value) if value is not None else None
    elif isinstance(tools, list) and tools:
        value = tools[0].get("name")
        return str(value) if value is not None else None
    return None


def _tool_version_from_metadata(tools: Any) -> Optional[str]:
    if isinstance(tools, dict):
        comps = tools.get("components") or []
        if comps:
            value = comps[0].get("version")
            return str(value) if value is not None else None
    elif isinstance(tools, list) and tools:
        value = tools[0].get("version")
        return str(value) if value is not None else None
    return None


def parse_crypto_components(
    components: List[Dict[str, Any]],
) -> List[ParsedCryptoAsset]:
    out: List[ParsedCryptoAsset] = []
    for idx, comp in enumerate(components):
        if comp.get("type") != "cryptographic-asset":
            continue
        try:
            asset = _parse_one(comp, idx)
            if asset is not None:
                out.append(asset)
        except Exception as e:
            logger.warning("cbom_parser: skipped component %s: %s", comp.get("bom-ref") or comp.get("name"), e)
    return out


def _parse_one(comp: Dict[str, Any], idx: int) -> Optional[ParsedCryptoAsset]:
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

    bom_ref = comp.get("bom-ref") or _synthesize_bom_ref(comp, idx)

    asset = ParsedCryptoAsset(
        bom_ref=bom_ref,
        name=name,
        asset_type=asset_type,
        properties=_extract_properties(comp),
    )

    if asset_type == CryptoAssetType.ALGORITHM:
        _populate_algorithm(asset, crypto_props.get("algorithmProperties") or {})
    elif asset_type == CryptoAssetType.CERTIFICATE:
        _populate_certificate(asset, crypto_props.get("certificateProperties") or {})
    elif asset_type == CryptoAssetType.PROTOCOL:
        _populate_protocol(asset, crypto_props.get("protocolProperties") or {})

    _populate_evidence(asset, comp.get("evidence") or {})
    return asset


def _populate_algorithm(asset: ParsedCryptoAsset, props: Dict[str, Any]) -> None:
    raw_prim = props.get("primitive")
    asset.primitive = _parse_primitive(raw_prim)
    asset.variant = props.get("variant")
    asset.parameter_set_identifier = props.get("parameterSetIdentifier")
    asset.mode = props.get("mode")
    asset.padding = props.get("padding")
    asset.curve = props.get("curve")

    key_size = props.get("parameterSetIdentifier")
    if key_size is not None:
        try:
            asset.key_size_bits = int(key_size)
        except (ValueError, TypeError):
            asset.key_size_bits = None


def _parse_primitive(raw: Any) -> Optional[CryptoPrimitive]:
    if raw is None:
        return None
    try:
        return CryptoPrimitive(raw)
    except ValueError:
        return CryptoPrimitive.OTHER


def _populate_certificate(asset: ParsedCryptoAsset, props: Dict[str, Any]) -> None:
    asset.subject_name = props.get("subjectName")
    asset.issuer_name = props.get("issuerName")
    asset.not_valid_before = _parse_iso_date(props.get("notValidBefore"))
    asset.not_valid_after = _parse_iso_date(props.get("notValidAfter"))
    asset.signature_algorithm_ref = props.get("signatureAlgorithmRef")
    asset.certificate_format = props.get("certificateFormat")


def _populate_protocol(asset: ParsedCryptoAsset, props: Dict[str, Any]) -> None:
    asset.protocol_type = props.get("type")
    asset.version = props.get("version")
    cipher_suites = props.get("cipherSuites") or []
    if isinstance(cipher_suites, list):
        asset.cipher_suites = [str(c) for c in cipher_suites]


def _populate_evidence(asset: ParsedCryptoAsset, evidence: Dict[str, Any]) -> None:
    occurrences = evidence.get("occurrences") or []
    asset.occurrence_locations = [
        str(o.get("location")) for o in occurrences if isinstance(o, dict) and o.get("location")
    ]
    detection = evidence.get("detectionContext")
    if isinstance(detection, str):
        asset.detection_context = detection
    confidence = evidence.get("confidence")
    if isinstance(confidence, (int, float)):
        asset.confidence = float(confidence)


def _extract_properties(comp: Dict[str, Any]) -> Dict[str, str]:
    props = {}
    for p in comp.get("properties") or []:
        name = p.get("name")
        value = p.get("value")
        if name and value is not None:
            props[str(name)] = str(value)
    return props


def _parse_iso_date(raw: Any) -> Optional[datetime]:
    if not raw or not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _synthesize_bom_ref(comp: Dict[str, Any], idx: int) -> str:
    basis = f"{comp.get('name', '')}|{idx}|{comp.get('cryptoProperties', {})}"
    return "synth-" + hashlib.sha256(basis.encode()).hexdigest()[:16]
