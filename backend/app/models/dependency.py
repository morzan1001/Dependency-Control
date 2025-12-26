import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Dependency(BaseModel):
    """
    Represents a flattened dependency for efficient searching and analytics.
    This is a 'derived' record from the raw SBOM.

    Supports data from:
    - CycloneDX (1.4, 1.5, 1.6)
    - SPDX (2.2, 2.3)
    - Syft JSON (native format)
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    project_id: str = Field(..., description="Reference to the project")
    scan_id: str = Field(..., description="Reference to the scan where this was found")

    # Core Identity
    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    purl: Optional[str] = Field(None, description="Package URL (unique identifier)")
    type: str = Field(
        "unknown",
        description="Package type (e.g. maven, npm, pypi, rpm, deb, go-module)",
    )

    # Licensing
    license: Optional[str] = Field(None, description="License expression or name")
    license_url: Optional[str] = Field(None, description="URL to license text")

    # Scope and relationships
    scope: Optional[str] = Field(
        None, description="Dependency scope (e.g. runtime, dev, optional)"
    )
    direct: bool = Field(
        False, description="True if direct dependency, False if transitive"
    )
    parent_components: List[str] = Field(
        default_factory=list, description="List of parent component PURLs/names"
    )

    # Source/Origin info (from SBOM properties)
    source_type: Optional[str] = Field(
        None, description="Source type: image, file-system, directory, application"
    )
    source_target: Optional[str] = Field(
        None, description="Source target: Docker image name, file path, etc."
    )
    layer_digest: Optional[str] = Field(
        None, description="Docker layer digest if from container image"
    )
    found_by: Optional[str] = Field(
        None,
        description="Cataloger/scanner that found this (e.g. python-pkg-cataloger)",
    )
    locations: List[str] = Field(
        default_factory=list, description="File paths where this package was found"
    )

    # Security identifiers
    cpes: List[str] = Field(
        default_factory=list, description="Common Platform Enumeration identifiers"
    )

    # Package metadata
    description: Optional[str] = Field(None, description="Package description")
    author: Optional[str] = Field(None, description="Package author/maintainer")
    publisher: Optional[str] = Field(None, description="Package publisher")
    group: Optional[str] = Field(
        None, description="Package group/namespace (e.g. Maven groupId)"
    )

    # External references
    homepage: Optional[str] = Field(None, description="Package homepage URL")
    repository_url: Optional[str] = Field(None, description="Source repository URL")
    download_url: Optional[str] = Field(None, description="Download URL")

    # Checksums/hashes
    hashes: Dict[str, str] = Field(
        default_factory=dict, description="Package hashes (e.g. {sha256: ...})"
    )

    # Additional metadata from SBOM properties
    properties: Dict[str, str] = Field(
        default_factory=dict,
        description="Additional SBOM properties as key-value pairs",
    )

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        populate_by_name = True
