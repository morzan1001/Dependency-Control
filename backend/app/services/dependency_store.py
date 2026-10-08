"""Replaces a scan's dependency documents with the parsed SBOMs', in chunked batches."""

from datetime import datetime, timezone

from app.models.dependency import Dependency
from app.repositories.dependencies import DependencyRepository
from app.schemas.sbom import ParsedDependency, ParsedSBOM
from app.services.sbom_parser import merge_duplicate_dependencies

_DEP_CHUNK_SIZE = 500
_FREE_TEXT_MAX_CHARS = 2048
_CLIP = ("license", "license_url", "description", "author", "publisher", "homepage", "repository_url", "download_url")


def _parsed_dep_to_dependency(
    parsed_dep: ParsedDependency, project_id: str, scan_id: str, written_at: datetime
) -> Dependency:
    fields = parsed_dep.model_dump()
    fields.update({name: text[:_FREE_TEXT_MAX_CHARS] for name in _CLIP if (text := fields[name])})
    return Dependency(**fields, project_id=project_id, scan_id=scan_id, created_at=written_at)


async def store_scan_dependencies(
    parsed_sboms: list[ParsedSBOM | None],
    project_id: str,
    scan_id: str,
    dep_repo: DependencyRepository,
) -> int | None:
    """Replace the scan's inventory with the payload's merged dependencies; writes nothing and returns None
    when an SBOM failed (None), so a re-run cannot swap a stored complete inventory for a partial one."""
    sboms = [sbom for sbom in parsed_sboms if sbom is not None]
    if not sboms or len(sboms) < len(parsed_sboms):
        return None
    merged, _ = merge_duplicate_dependencies([dep for sbom in sboms for dep in sbom.dependencies])
    # Deletes only rows no write since this one has touched, so after a failure part-way or an
    # overlapping store of the same scan the newest write's rows are all still there.
    written_at = datetime.now(timezone.utc)
    fresh = not await dep_repo.exists({"scan_id": scan_id})
    for start in range(0, len(merged), _DEP_CHUNK_SIZE):
        chunk = merged[start : start + _DEP_CHUNK_SIZE]
        await dep_repo.upsert_many(
            [_parsed_dep_to_dependency(dep, project_id, scan_id, written_at) for dep in chunk], fresh
        )
    await dep_repo.delete_older_writes({"scan_id": scan_id}, written_at)
    return len(merged)
