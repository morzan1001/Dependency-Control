"""Per-scan update-frequency rollup documents."""

from datetime import datetime, timezone

from pydantic import BaseModel, Field

from app.models.types import MongoDocument, PyObjectId

UPDATE_DELTA_SCHEMA_VERSION = 1


def _now() -> datetime:
    return datetime.now(timezone.utc)


class UpdateCounts(BaseModel):
    patch: int = 0
    minor: int = 0
    major: int = 0
    unknown: int = 0
    downgrade: int = 0


class UpdateSample(BaseModel):
    """One update event, field names kept short because the array is stored per scan."""

    n: str  # display name
    t: str  # package type
    p: str | None = None  # purl
    ov: str  # old version
    nv: str  # new version
    k: str  # kind: patch|minor|major|unknown|downgrade
    wo: bool  # was flagged outdated in the previous scan


class ScanUpdateDelta(MongoDocument):
    """Dependency-version movement of one scan against its predecessor on the same branch."""

    id: PyObjectId = Field(..., validation_alias="_id", serialization_alias="_id")
    project_id: str
    branch: str
    scan_created_at: datetime
    commit_hash: str | None = None
    prev_scan_id: str | None = None
    prev_created_at: datetime | None = None
    is_baseline: bool = False
    # 0 marks an SBOM-less scan; such a scan is never chosen as a predecessor.
    dep_count: int = 0
    updates: UpdateCounts = Field(default_factory=UpdateCounts)
    # Downgrades are excluded: a rollback is not update activity.
    total_updates: int = 0
    # None marks a scan without outdated analysis; 0 means the analysis found nothing.
    outdated_count: int | None = None
    # Packages outdated here that the predecessor did not report as outdated,
    # or the whole set when the predecessor carried no outdated analysis.
    outdated_added: list[str] = Field(default_factory=list)
    outdated_resolved: list[str] = Field(default_factory=list)
    eco: dict[str, int] = Field(default_factory=dict)
    updates_sample: list[UpdateSample] = Field(default_factory=list)
    # Set when the computation failed; the document still exists so that
    # count(deltas) == count(usable scans) stays a reconcile invariant.
    error: str | None = None
    schema_version: int = UPDATE_DELTA_SCHEMA_VERSION
    computed_at: datetime = Field(default_factory=_now)


class ScanOutdatedSet(MongoDocument):
    """Full outdated-package set of one scan, kept apart from the delta read path."""

    id: PyObjectId = Field(..., validation_alias="_id", serialization_alias="_id")
    names: list[str] = Field(default_factory=list)
    n: int = 0
    scan_created_at: datetime
    schema_version: int = UPDATE_DELTA_SCHEMA_VERSION
