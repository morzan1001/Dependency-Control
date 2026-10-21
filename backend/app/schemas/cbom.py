from typing import Any

from pydantic import ConfigDict, Field

from app.models.crypto_asset import CryptoAssetFields, CryptoPrimitive
from app.schemas.ingest import IngestEnvelope

QUANTUM_VULNERABLE_PRIMITIVES: frozenset[CryptoPrimitive] = frozenset(
    {CryptoPrimitive.PKE, CryptoPrimitive.SIGNATURE, CryptoPrimitive.KEM, CryptoPrimitive.KEY_AGREE}
)


class ParsedCryptoAsset(CryptoAssetFields):
    # The parser assigns raw document values; checking each one confines a bad value to its own component.
    model_config = ConfigDict(validate_assignment=True, coerce_numbers_to_str=True)


class CBOMIngest(IngestEnvelope):
    cbom: dict[str, Any] = Field(..., description="CycloneDX 1.6 CBOM payload")
