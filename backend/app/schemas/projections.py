"""
Pydantic schemas for database projections.

These schemas define minimal models for performance-critical queries
that only need specific fields.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.stats import Stats
from app.models.types import PyObjectId


class ProjectIdOnly(BaseModel):
    """Project with only ID field."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")


class ProjectMinimal(BaseModel):
    """Project with ID and name only (for lookups/maps)."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    name: str

    model_config = ConfigDict(populate_by_name=True)


class ProjectWithScanId(BaseModel):
    """Project with ID, name, latest scan ID, and deleted branches."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    name: str
    latest_scan_id: Optional[str] = None
    deleted_branches: List[str] = Field(default_factory=list)

    model_config = ConfigDict(populate_by_name=True)


class ScanWithStats(BaseModel):
    """Scan with ID and stats."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    stats: Optional[Stats] = None

    model_config = ConfigDict(populate_by_name=True)


class ScanMinimal(BaseModel):
    """Scan with minimal fields for lookups."""

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    pipeline_id: Optional[int] = None
    is_rescan: Optional[bool] = None
    original_scan_id: Optional[str] = None
    status: Optional[str] = None
    reachability_pending: Optional[bool] = None
    project_id: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)


class CallgraphMinimal(BaseModel):
    """Callgraph with minimal fields.

    ``import_map`` ({file: [modules]}) is not persisted; it is derived below
    from the raw ``imports`` list, or from the aggregated ``module_usage`` map
    when only the minimal projection is loaded. It always resolves to a dict.
    """

    id: PyObjectId = Field(validation_alias="_id", serialization_alias="_id")
    module_usage: Optional[dict] = None
    imports: List[dict] = Field(default_factory=list)
    import_map: dict = Field(default_factory=dict)
    language: Optional[str] = None

    model_config = ConfigDict(populate_by_name=True)

    @model_validator(mode="after")
    def _derive_import_map(self) -> "CallgraphMinimal":
        if self.import_map:
            return self
        # Prefer the raw imports list; fall back to the module_usage map, which
        # the minimal projection includes.
        self.import_map = _import_map_from_imports(self.imports) or _import_map_from_module_usage(self.module_usage)
        return self


def _field(entry: object, name: str):
    """Read ``name`` from a dict or attribute-style entry."""
    if isinstance(entry, dict):
        return entry.get(name)
    return getattr(entry, name, None)


def _import_map_from_imports(imports: List[dict]) -> Dict[str, List[str]]:
    """Build {file: [module, ...]} from a raw imports list (ImportEntry-like)."""
    derived: Dict[str, List[str]] = {}
    for entry in imports:
        file_path = _field(entry, "file")
        module = _field(entry, "module")
        if file_path and module:
            derived.setdefault(file_path, []).append(module)
    return derived


def _import_map_from_module_usage(module_usage: Optional[dict]) -> Dict[str, List[str]]:
    """Invert an aggregated module_usage map into {file: [module, ...]}.

    Each usage entry maps a module to the files importing it
    (``import_locations``); this inverts that so the minimal projection (which
    includes ``module_usage`` but not the raw imports) yields real data.
    """
    derived: Dict[str, List[str]] = {}
    if not module_usage:
        return derived
    for key, usage in module_usage.items():
        module = _field(usage, "module") or key
        locations = _field(usage, "import_locations") or []
        if not module:
            continue
        for file_path in locations:
            if file_path:
                derived.setdefault(file_path, []).append(module)
    return derived
