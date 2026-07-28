"""Normalized in-memory CBOM representation produced by the CBOM parser."""

from datetime import datetime
from enum import Enum

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
    primitive: CryptoPrimitive | None = None
    variant: str | None = None
    parameter_set_identifier: str | None = None
    mode: str | None = None
    padding: str | None = None
    key_size_bits: int | None = None
    curve: str | None = None

    # Certificate-only
    subject_name: str | None = None
    issuer_name: str | None = None
    not_valid_before: datetime | None = None
    not_valid_after: datetime | None = None
    signature_algorithm_ref: str | None = None
    subject_public_key_ref: str | None = None
    certificate_format: str | None = None

    # Protocol-only
    protocol_type: str | None = None
    version: str | None = None
    cipher_suites: list[str] = Field(default_factory=list)

    # Context
    occurrence_locations: list[str] = Field(default_factory=list)
    detection_context: str | None = None
    confidence: float | None = None
    related_dependency_purls: list[str] = Field(default_factory=list)

    properties: dict[str, str] = Field(default_factory=dict)


class ParsedCBOM(BaseModel):
    """Normalized CBOM representation produced by parse_cbom()."""

    format_version: str | None = None
    tool_name: str | None = None
    tool_version: str | None = None
    created_at: str | None = None

    assets: list[ParsedCryptoAsset] = Field(default_factory=list)

    total_components: int = 0
    parsed_components: int = 0
    skipped_components: int = 0
