"""Pydantic models for normalized SBOM representations (CycloneDX, SPDX, Syft)."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.cbom import ParsedCryptoAsset


class SBOMFormat(Enum):
    """Supported SBOM formats."""

    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    SYFT = "syft"
    UNKNOWN = "unknown"


class SourceType(Enum):
    """Source types for SBOM origin."""

    IMAGE = "image"
    DIRECTORY = "directory"
    FILE = "file"
    APPLICATION = "application"
    FILESYSTEM = "file-system"
    UNKNOWN = "unknown"


class ParsedDependency(BaseModel):
    """Normalized dependency representation with all available SBOM fields."""

    # Core Identity
    name: str
    version: str
    purl: str | None = None
    type: str = "unknown"

    # Licensing
    license: str = ""
    license_url: str | None = None

    # Scope and relationships
    scope: str | None = None
    direct: bool = False
    direct_inferred: bool = Field(
        False,
        description="True if 'direct' is a guess (no graph, ref absent from the graph, or fallback root resolution)",
    )
    parent_components: list[str] = Field(default_factory=list)

    # Source/Origin information
    source_type: str | None = None
    source_target: str | None = None
    layer_digest: str | None = None
    found_by: str | None = None
    locations: list[str] = Field(default_factory=list)

    # Security identifiers
    cpes: list[str] = Field(default_factory=list)

    # Package metadata
    description: str | None = None
    author: str | None = None
    publisher: str | None = None
    group: str | None = None

    # External references
    homepage: str | None = None
    repository_url: str | None = None
    download_url: str | None = None

    # Checksums
    hashes: dict[str, str] = Field(default_factory=dict)

    # Additional properties from SBOM
    properties: dict[str, str] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()


class ParsedSBOM(BaseModel):
    """Normalized SBOM representation."""

    format: SBOMFormat
    format_version: str | None = None

    # Source information
    source_type: str | None = None
    source_target: str | None = None

    # Components/Dependencies
    dependencies: list[ParsedDependency] = Field(default_factory=list)

    # Metadata
    tool_name: str | None = None
    tool_version: str | None = None
    created_at: str | None = None

    # Statistics
    total_components: int = 0
    parsed_components: int = 0
    skipped_components: int = 0

    # CBOM extension — populated if SBOM contains cryptographic-asset components
    crypto_assets: list["ParsedCryptoAsset"] = Field(default_factory=list)
