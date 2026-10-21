from enum import Enum

from pydantic import BaseModel, Field

from app.models.dependency import DependencyFields
from app.schemas.cbom import ParsedCryptoAsset

UNKNOWN_VERSION = "unknown"


def has_known_version(version: str | None) -> bool:
    return bool(version) and version != UNKNOWN_VERSION


class SBOMFormat(Enum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    SYFT = "syft"
    UNKNOWN = "unknown"


class ParsedDependency(DependencyFields):
    # An undeclared license parses as "", the value stored rows have always held for it.
    license: str = ""


class ParsedSBOM(BaseModel):
    format: SBOMFormat

    source_type: str | None = None
    source_target: str | None = None

    dependencies: list[ParsedDependency] = Field(default_factory=list)

    skipped_components: int = 0
    merged_components: int = 0
    skipped_reasons: dict[str, int] = Field(default_factory=dict)

    # Filled only when the SBOM holds cryptographic-asset components.
    crypto_assets: list["ParsedCryptoAsset"] = Field(default_factory=list)
