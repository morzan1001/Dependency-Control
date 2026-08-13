"""Replaces a scan's dependency documents with the parsed SBOM's, in chunked batches."""

import logging

from app.models.dependency import Dependency
from app.repositories import DependencyRepository
from app.schemas.sbom import ParsedDependency, ParsedSBOM

logger = logging.getLogger(__name__)

_DEP_CHUNK_SIZE = 500


def _parsed_dep_to_dependency(parsed_dep: ParsedDependency, project_id: str, scan_id: str) -> Dependency:
    return Dependency(
        project_id=project_id,
        scan_id=scan_id,
        name=parsed_dep.name,
        version=parsed_dep.version,
        purl=parsed_dep.purl,
        type=parsed_dep.type,
        license=parsed_dep.license,
        license_url=parsed_dep.license_url,
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
        description=parsed_dep.description,
        author=parsed_dep.author,
        publisher=parsed_dep.publisher,
        group=parsed_dep.group,
        homepage=parsed_dep.homepage,
        repository_url=parsed_dep.repository_url,
        download_url=parsed_dep.download_url,
        hashes=parsed_dep.hashes,
        properties=parsed_dep.properties,
    )


async def _insert_dependencies_chunked(
    parsed_sbom: ParsedSBOM,
    project_id: str,
    scan_id: str,
    dep_repo: DependencyRepository,
) -> int:
    total_inserted = 0
    chunk: list[dict] = []
    for parsed_dep in parsed_sbom.dependencies:
        dep = _parsed_dep_to_dependency(parsed_dep, project_id, scan_id)
        chunk.append(dep.model_dump(by_alias=True))
        if len(chunk) >= _DEP_CHUNK_SIZE:
            total_inserted += await dep_repo.create_many_raw(chunk)
            chunk.clear()
    if chunk:
        total_inserted += await dep_repo.create_many_raw(chunk)
        chunk.clear()
    return total_inserted


async def store_sbom_dependencies(
    parsed_sbom: ParsedSBOM,
    project_id: str,
    scan_id: str,
    dep_repo: DependencyRepository,
    old_deps_deleted: bool,
) -> tuple[int, bool]:
    """Delete the scan's old deps once per run, then insert in chunks; returns (inserted, old_deps_deleted)."""
    if not old_deps_deleted:
        deleted_count = await dep_repo.delete_by_scan(scan_id)
        if deleted_count:
            logger.debug(f"Deleted {deleted_count} old dependencies for scan {scan_id}")
        old_deps_deleted = True

    inserted = await _insert_dependencies_chunked(parsed_sbom, project_id, scan_id, dep_repo)
    return inserted, old_deps_deleted
