from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from app.core.purl import CopyKey, dependency_copy_key
from app.models.dependency import Dependency
from app.repositories.dependencies import DependencyRepository
from app.schemas.sbom import ParsedDependency, ParsedSBOM
from app.services.sbom_parser import merge_duplicate_dependencies

_DEP_CHUNK_SIZE = 500
_FREE_TEXT_MAX_CHARS = 2048
_CLIP = ("license", "license_url", "description", "author", "publisher", "homepage", "repository_url", "download_url")


def _parsed_dep_to_dependency(
    parsed_dep: ParsedDependency,
    project_id: str,
    scan_id: str,
    written_at: datetime,
    copies: Mapping[CopyKey, dict[str, Any]],
) -> Dependency:
    fields = parsed_dep.model_dump()
    fields.update({name: text[:_FREE_TEXT_MAX_CHARS] for name in _CLIP if (text := fields[name])})
    copied = copies.get(dependency_copy_key(fields["purl"], fields["name"], fields["version"]), {})
    # The SBOM-declared license is authoritative; a copied one only fills a dependency that lacks it.
    fields.update({key: value for key, value in copied.items() if key != "license" or not fields["license"]})
    return Dependency(**fields, project_id=project_id, scan_id=scan_id, created_at=written_at)


async def store_scan_dependencies(
    parsed_sboms: list[ParsedSBOM | None],
    project_id: str,
    scan_id: str,
    dep_repo: DependencyRepository,
    copies: Mapping[CopyKey, dict[str, Any]] | None = None,
) -> int | None:
    """Writes nothing when an SBOM failed (None) so a re-run cannot replace a complete inventory with a partial one."""
    sboms = [sbom for sbom in parsed_sboms if sbom is not None]
    if not sboms or len(sboms) < len(parsed_sboms):
        return None
    merged, _ = merge_duplicate_dependencies([dep for sbom in sboms for dep in sbom.dependencies])
    copies = copies or {}
    # Only rows no later write touched are deleted, so a failed or overlapping store keeps the newest rows.
    written_at = datetime.now(timezone.utc)
    fresh = not await dep_repo.exists({"scan_id": scan_id})
    for start in range(0, len(merged), _DEP_CHUNK_SIZE):
        chunk = merged[start : start + _DEP_CHUNK_SIZE]
        await dep_repo.upsert_many(
            [_parsed_dep_to_dependency(dep, project_id, scan_id, written_at, copies) for dep in chunk], fresh
        )
    await dep_repo.delete_older_writes({"scan_id": scan_id}, written_at)
    return len(merged)
