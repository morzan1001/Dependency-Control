"""
CryptoAsset MongoDB model.

Stored in collection `crypto_assets`. One document per detected cryptographic
component (algorithm, certificate, protocol, related-crypto-material) per scan.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.types import PyObjectId
from app.schemas.cbom import CryptoAssetType, CryptoPrimitive


class CryptoAsset(BaseModel):
    id: PyObjectId = Field(
        default_factory=lambda: str(uuid.uuid4()),
        validation_alias="_id",
        serialization_alias="_id",
    )
    project_id: str
    scan_id: str

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

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(populate_by_name=True, use_enum_values=True)
