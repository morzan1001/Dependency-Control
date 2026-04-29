"""
CryptoAsset MongoDB model.

Stored in collection `crypto_assets`. One document per detected cryptographic
component (algorithm, certificate, protocol, related-crypto-material) per scan.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import Field

from app.models.types import MongoDocument, PyObjectId
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


class CryptoAsset(MongoDocument):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    project_id: str = Field(..., description="Reference to the project")
    scan_id: str = Field(..., description="Reference to the scan where this was found")

    bom_ref: str = Field(..., description="Stable bill-of-materials reference within a CBOM payload")
    name: str = Field(..., description="Crypto asset name (e.g. SHA-256, TLS, cert:CN=foo)")
    asset_type: CryptoAssetType = Field(
        ..., description="Type of crypto asset: algorithm, certificate, protocol, or related-crypto-material"
    )

    # Algorithm-only
    primitive: Optional[CryptoPrimitive] = Field(
        None, description="Cryptographic primitive classification for algorithm assets (hash, block-cipher, pke, etc.)"
    )
    variant: Optional[str] = Field(None, description="Algorithm variant/instance (e.g. 'RSA-OAEP', 'AES-256-GCM')")
    parameter_set_identifier: Optional[str] = Field(
        None, description="Parameter set identifier from CycloneDX (often key size as string)"
    )
    mode: Optional[str] = Field(None, description="Cipher mode (e.g. GCM, CBC, OFB) for algorithm assets")
    padding: Optional[str] = Field(None, description="Padding scheme (e.g. PKCS1v15, OAEP, PSS) for algorithm assets")
    key_size_bits: Optional[int] = Field(None, description="Key size in bits for algorithm assets")
    curve: Optional[str] = Field(None, description="Elliptic curve identifier (e.g. P-256, secp384r1)")

    # Certificate-only
    subject_name: Optional[str] = Field(None, description="X.509 subject distinguished name for certificate assets")
    issuer_name: Optional[str] = Field(None, description="X.509 issuer distinguished name for certificate assets")
    not_valid_before: Optional[datetime] = Field(None, description="Certificate validity start timestamp")
    not_valid_after: Optional[datetime] = Field(None, description="Certificate validity end timestamp")
    signature_algorithm_ref: Optional[str] = Field(
        None, description="bom-ref of the algorithm used to sign this certificate"
    )
    certificate_format: Optional[str] = Field(None, description="Certificate format identifier (e.g. X.509)")

    # Protocol-only
    protocol_type: Optional[str] = Field(
        None, description="Protocol identifier (e.g. tls, ssh, ipsec) for protocol assets"
    )
    version: Optional[str] = Field(None, description="Protocol version string (e.g. '1.2', '1.3')")
    cipher_suites: List[str] = Field(
        default_factory=list, description="Cipher suites advertised/negotiated by a protocol asset"
    )

    # Context
    occurrence_locations: List[str] = Field(
        default_factory=list, description="Source locations (file paths, binary offsets) where this asset was detected"
    )
    detection_context: Optional[str] = Field(None, description="Where detection happened (e.g. source, binary, config)")
    confidence: Optional[float] = Field(None, description="Detection confidence 0.0–1.0 as reported by the scanner")
    related_dependency_purls: List[str] = Field(
        default_factory=list, description="PURLs of software components linked to this crypto asset"
    )

    properties: Dict[str, str] = Field(
        default_factory=dict, description="Passthrough of additional CycloneDX properties"
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Persistence timestamp (UTC)"
    )
