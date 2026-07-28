"""CryptoAsset model (collection `crypto_assets`): one document per detected cryptographic component per scan."""

from datetime import datetime, timezone

from pydantic import Field

from app.models.types import MongoDocument
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


class CryptoAsset(MongoDocument):
    project_id: str = Field(..., description="Reference to the project")
    scan_id: str = Field(..., description="Reference to the scan where this was found")

    bom_ref: str = Field(..., description="Stable bill-of-materials reference within a CBOM payload")
    name: str = Field(..., description="Crypto asset name (e.g. SHA-256, TLS, cert:CN=foo)")
    asset_type: CryptoAssetType = Field(
        ..., description="Type of crypto asset: algorithm, certificate, protocol, or related-crypto-material"
    )

    # Algorithm-only
    primitive: CryptoPrimitive | None = Field(
        None, description="Cryptographic primitive classification for algorithm assets (hash, block-cipher, pke, etc.)"
    )
    variant: str | None = Field(None, description="Algorithm variant/instance (e.g. 'RSA-OAEP', 'AES-256-GCM')")
    parameter_set_identifier: str | None = Field(
        None, description="Parameter set identifier from CycloneDX (often key size as string)"
    )
    mode: str | None = Field(None, description="Cipher mode (e.g. GCM, CBC, OFB) for algorithm assets")
    padding: str | None = Field(None, description="Padding scheme (e.g. PKCS1v15, OAEP, PSS) for algorithm assets")
    key_size_bits: int | None = Field(None, description="Key size in bits for algorithm assets")
    curve: str | None = Field(None, description="Elliptic curve identifier (e.g. P-256, secp384r1)")

    # Certificate-only
    subject_name: str | None = Field(None, description="X.509 subject distinguished name for certificate assets")
    issuer_name: str | None = Field(None, description="X.509 issuer distinguished name for certificate assets")
    not_valid_before: datetime | None = Field(None, description="Certificate validity start timestamp")
    not_valid_after: datetime | None = Field(None, description="Certificate validity end timestamp")
    signature_algorithm_ref: str | None = Field(
        None, description="bom-ref of the algorithm used to sign this certificate (the CA's signing key)"
    )
    subject_public_key_ref: str | None = Field(
        None, description="bom-ref of the algorithm asset representing this certificate's own subject public key"
    )
    certificate_format: str | None = Field(None, description="Certificate format identifier (e.g. X.509)")

    # Protocol-only
    protocol_type: str | None = Field(
        None, description="Protocol identifier (e.g. tls, ssh, ipsec) for protocol assets"
    )
    version: str | None = Field(None, description="Protocol version string (e.g. '1.2', '1.3')")
    cipher_suites: list[str] = Field(
        default_factory=list, description="Cipher suites advertised/negotiated by a protocol asset"
    )

    # Context
    occurrence_locations: list[str] = Field(
        default_factory=list, description="Source locations (file paths, binary offsets) where this asset was detected"
    )
    detection_context: str | None = Field(None, description="Where detection happened (e.g. source, binary, config)")
    confidence: float | None = Field(None, description="Detection confidence 0.0–1.0 as reported by the scanner")
    related_dependency_purls: list[str] = Field(
        default_factory=list, description="PURLs of software components linked to this crypto asset"
    )

    properties: dict[str, str] = Field(
        default_factory=dict, description="Passthrough of additional CycloneDX properties"
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Persistence timestamp (UTC)"
    )
