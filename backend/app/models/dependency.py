from pydantic import BaseModel, Field

from app.models.base import CreatedAtModel
from app.models.types import MongoDocument


class DependencyFields(BaseModel):
    name: str = Field(..., description="Package name")
    version: str = Field(..., description="Package version")
    purl: str | None = Field(None, description="Package URL (unique identifier)")
    type: str = Field(
        "unknown",
        description="Package type (e.g. maven, npm, pypi, rpm, deb, go-module)",
    )

    license: str | None = Field(None, description="License expression or name")
    license_url: str | None = Field(None, description="URL to license text")

    scope: str | None = Field(None, description="Dependency scope (e.g. runtime, dev, optional)")
    direct: bool = Field(False, description="True if direct dependency, False if transitive")
    direct_inferred: bool = Field(
        False,
        description="True if 'direct' is a guess (no graph, ref absent from the graph, or fallback root resolution)",
    )
    parent_components: list[str] = Field(default_factory=list, description="The parents' dependency_node_key values")

    source_type: str | None = Field(None, description="Source type: image, directory, file, application")
    source_target: str | None = Field(None, description="Source target: Docker image name, file path, etc.")
    layer_digest: str | None = Field(None, description="Docker layer digest if from container image")
    found_by: str | None = Field(
        None,
        description="Cataloger/scanner that found this (e.g. python-pkg-cataloger)",
    )
    locations: list[str] = Field(default_factory=list, description="File paths where this package was found")

    cpes: list[str] = Field(default_factory=list, description="Common Platform Enumeration identifiers")

    description: str | None = Field(None, description="Package description")
    author: str | None = Field(None, description="Package author/maintainer")
    publisher: str | None = Field(None, description="Package publisher")
    group: str | None = Field(None, description="Package group/namespace (e.g. Maven groupId)")

    homepage: str | None = Field(None, description="Package homepage URL")
    repository_url: str | None = Field(None, description="Source repository URL")
    download_url: str | None = Field(None, description="Download URL")

    hashes: dict[str, str] = Field(default_factory=dict, description="Package hashes (e.g. {sha256: ...})")

    properties: dict[str, str] = Field(
        default_factory=dict,
        description="Additional SBOM properties as key-value pairs",
    )


class Dependency(MongoDocument, CreatedAtModel, DependencyFields):
    project_id: str = Field(..., description="Reference to the project")
    scan_id: str = Field(..., description="Reference to the scan where this was found")

    license_category: str | None = Field(None, description="License category the analysis copies from the license scan")
    license_expression: str | None = Field(
        None, description="SPDX expression the analysis copies from the license scan"
    )
    license_risks: list[str] | None = Field(None, description="License risks the analysis copies from the license scan")
