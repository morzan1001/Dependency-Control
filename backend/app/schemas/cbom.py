"""
CBOM Schema Definitions

Normalized in-memory representation produced by cbom_parser.py.
Mirrors Pydantic conventions of schemas/sbom.py.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class CryptoAssetType(str, Enum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"


class CryptoPrimitive(str, Enum):
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    HASH = "hash"
    MAC = "mac"
    PKE = "pke"
    SIGNATURE = "signature"
    KEM = "kem"
    KDF = "kdf"
    DRBG = "drbg"
    OTHER = "other"


class ParsedCryptoAsset(BaseModel):
    """Normalized crypto asset from CycloneDX 1.6 cryptoProperties."""

    bom_ref: str
    name: str
    asset_type: CryptoAssetType

    # Algorithm-only
    primitive: Optional[CryptoPrimitive] = None
    variant: Optional[str] = None
    parameter_set_identifier: Optional[str] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    key_size_bits: Optional[int] = None
    curve: Optional[str] = None

    # Certificate-only
    subject_name: Optional[str] = None
    issuer_name: Optional[str] = None
    not_valid_before: Optional[datetime] = None
    not_valid_after: Optional[datetime] = None
    signature_algorithm_ref: Optional[str] = None
    certificate_format: Optional[str] = None

    # Protocol-only
    protocol_type: Optional[str] = None
    version: Optional[str] = None
    cipher_suites: List[str] = Field(default_factory=list)

    # Context
    occurrence_locations: List[str] = Field(default_factory=list)
    detection_context: Optional[str] = None
    confidence: Optional[float] = None
    related_dependency_purls: List[str] = Field(default_factory=list)

    properties: Dict[str, str] = Field(default_factory=dict)


class ParsedCBOM(BaseModel):
    """Normalized CBOM representation produced by parse_cbom()."""

    format_version: Optional[str] = None
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None
    created_at: Optional[str] = None

    assets: List[ParsedCryptoAsset] = Field(default_factory=list)

    total_components: int = 0
    parsed_components: int = 0
    skipped_components: int = 0
