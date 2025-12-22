"""
SBOM Schema Definitions

Data classes for normalized SBOM representations.
Supports CycloneDX, SPDX, and Syft formats.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


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


@dataclass
class ParsedDependency:
    """Normalized dependency representation with all available SBOM fields."""

    # Core Identity
    name: str
    version: str
    purl: Optional[str] = None
    type: str = "unknown"

    # Licensing
    license: str = ""
    license_url: Optional[str] = None

    # Scope and relationships
    scope: Optional[str] = None
    direct: bool = False
    parent_components: List[str] = field(default_factory=list)

    # Source/Origin information
    source_type: Optional[str] = None
    source_target: Optional[str] = None
    layer_digest: Optional[str] = None
    found_by: Optional[str] = None
    locations: List[str] = field(default_factory=list)

    # Security identifiers
    cpes: List[str] = field(default_factory=list)

    # Package metadata
    description: Optional[str] = None
    author: Optional[str] = None
    publisher: Optional[str] = None
    group: Optional[str] = None

    # External references
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    download_url: Optional[str] = None

    # Checksums
    hashes: Dict[str, str] = field(default_factory=dict)

    # Additional properties from SBOM
    properties: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "type": self.type,
            "license": self.license,
            "license_url": self.license_url,
            "scope": self.scope,
            "direct": self.direct,
            "parent_components": self.parent_components,
            "source_type": self.source_type,
            "source_target": self.source_target,
            "layer_digest": self.layer_digest,
            "found_by": self.found_by,
            "locations": self.locations,
            "cpes": self.cpes,
            "description": self.description,
            "author": self.author,
            "publisher": self.publisher,
            "group": self.group,
            "homepage": self.homepage,
            "repository_url": self.repository_url,
            "download_url": self.download_url,
            "hashes": self.hashes,
            "properties": self.properties,
        }


@dataclass
class ParsedSBOM:
    """Normalized SBOM representation."""

    format: SBOMFormat
    format_version: Optional[str] = None

    # Source information
    source_type: Optional[str] = None
    source_target: Optional[str] = None

    # Components/Dependencies
    dependencies: List[ParsedDependency] = field(default_factory=list)

    # Metadata
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None
    created_at: Optional[str] = None

    # Statistics
    total_components: int = 0
    parsed_components: int = 0
    skipped_components: int = 0
