from datetime import datetime, timezone

from pydantic import Field

from app.models.types import MongoDocument


class Dependency(MongoDocument):
    """Flattened dependency derived from the raw SBOM (CycloneDX, SPDX, Syft JSON) for search and analytics."""

    project_id: str = Field(..., description="Reference to the project")
    scan_id: str = Field(..., description="Reference to the scan where this was found")

    # Core Identity
    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    purl: str | None = Field(None, description="Package URL (unique identifier)")
    type: str = Field(
        "unknown",
        description="Package type (e.g. maven, npm, pypi, rpm, deb, go-module)",
    )

    # Licensing
    license: str | None = Field(None, description="License expression or name")
    license_url: str | None = Field(None, description="URL to license text")

    # Scope and relationships
    scope: str | None = Field(None, description="Dependency scope (e.g. runtime, dev, optional)")
    direct: bool = Field(False, description="True if direct dependency, False if transitive")
    direct_inferred: bool = Field(
        False,
        description="True if 'direct' was inferred (SBOM had no dependency graph)",
    )
    parent_components: list[str] = Field(default_factory=list, description="List of parent component PURLs/names")

    # Source/Origin info (from SBOM properties)
    source_type: str | None = Field(None, description="Source type: image, file-system, directory, application")
    source_target: str | None = Field(None, description="Source target: Docker image name, file path, etc.")
    layer_digest: str | None = Field(None, description="Docker layer digest if from container image")
    found_by: str | None = Field(
        None,
        description="Cataloger/scanner that found this (e.g. python-pkg-cataloger)",
    )
    locations: list[str] = Field(default_factory=list, description="File paths where this package was found")

    # Security identifiers
    cpes: list[str] = Field(default_factory=list, description="Common Platform Enumeration identifiers")

    # Package metadata
    description: str | None = Field(None, description="Package description")
    author: str | None = Field(None, description="Package author/maintainer")
    publisher: str | None = Field(None, description="Package publisher")
    group: str | None = Field(None, description="Package group/namespace (e.g. Maven groupId)")

    # External references
    homepage: str | None = Field(None, description="Package homepage URL")
    repository_url: str | None = Field(None, description="Source repository URL")
    download_url: str | None = Field(None, description="Download URL")

    # Checksums/hashes
    hashes: dict[str, str] = Field(default_factory=dict, description="Package hashes (e.g. {sha256: ...})")

    # Additional metadata from SBOM properties
    properties: dict[str, str] = Field(
        default_factory=dict,
        description="Additional SBOM properties as key-value pairs",
    )

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
