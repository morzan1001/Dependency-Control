"""Replaces a scan's dependency documents with the parsed SBOMs', in chunked batches."""

from datetime import datetime, timezone

from app.models.dependency import Dependency
from app.repositories.dependencies import DependencyRepository
from app.schemas.sbom import ParsedDependency, ParsedSBOM
from app.services.sbom_parser import merge_duplicate_dependencies

_DEP_CHUNK_SIZE = 500
_FREE_TEXT_MAX_CHARS = 2048


def _clip(text: str | None) -> str | None:
    return text[:_FREE_TEXT_MAX_CHARS] if text else text


def _parsed_dep_to_dependency(
    parsed_dep: ParsedDependency, project_id: str, scan_id: str, written_at: datetime
) -> Dependency:
    return Dependency(
        project_id=project_id,
        scan_id=scan_id,
        created_at=written_at,
        name=parsed_dep.name,
        version=parsed_dep.version,
        purl=parsed_dep.purl,
        type=parsed_dep.type,
        license=_clip(parsed_dep.license),
        license_url=_clip(parsed_dep.license_url),
        scope=parsed_dep.scope,
        direct=parsed_dep.direct,
        direct_inferred=parsed_dep.direct_inferred,
        parent_components=parsed_dep.parent_components,
        source_type=parsed_dep.source_type,
        source_target=parsed_dep.source_target,
        layer_digest=parsed_dep.layer_digest,
        found_by=parsed_dep.found_by,
        locations=parsed_dep.locations,
        cpes=parsed_dep.cpes,
        description=_clip(parsed_dep.description),
        author=_clip(parsed_dep.author),
        publisher=_clip(parsed_dep.publisher),
        group=parsed_dep.group,
        homepage=_clip(parsed_dep.homepage),
        repository_url=_clip(parsed_dep.repository_url),
        download_url=_clip(parsed_dep.download_url),
        hashes=parsed_dep.hashes,
        properties=parsed_dep.properties,
    )


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
    for start in range(0, len(merged), _DEP_CHUNK_SIZE):
        chunk = merged[start : start + _DEP_CHUNK_SIZE]
        await dep_repo.upsert_many([_parsed_dep_to_dependency(dep, project_id, scan_id, written_at) for dep in chunk])
    await dep_repo.delete_older_writes({"scan_id": scan_id}, written_at)
    return len(merged)
