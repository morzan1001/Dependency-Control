"""Endpoints for uploading and querying call graph data for reachability analysis."""

import asyncio
import logging
from typing import Any

from fastapi import HTTPException

from app.api.deps import CallgraphWriteDep, CurrentUserDep, DatabaseDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.callgraph import (
    callgraph_entry_count,
    check_callgraph_access,
    detect_format,
    parse_generic_format,
    parse_madge_format,
)
from app.api.v1.helpers.responses import RESP_AUTH_400, RESP_AUTH_404
from app.core.constants import CALLGRAPH_MAX_ENTRIES
from app.models.callgraph import CallEdge, Callgraph, ImportEntry, ModuleUsage
from app.repositories import CallgraphRepository, ScanRepository
from app.schemas.callgraph import (
    CallgraphResponse,
    CallgraphUploadRequest,
    CallgraphUploadResponse,
    DeleteCallgraphResponse,
    ModuleUsageResponse,
)
from app.services.component_identity import canonical_callgraph_language
from app.services.reachability_enrichment import run_pending_reachability_for_scan
from app.services.scan_manager import deterministic_scan_id

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


_FORMAT_LANGUAGE_MAP = {"madge": "javascript"}

_FORMAT_PARSERS = {
    "madge": parse_madge_format,
    "generic": parse_generic_format,
}


def _resolve_format(request_format: str, data: dict[str, Any]) -> str:
    """Resolve the callgraph format, auto-detecting if needed."""
    if request_format != "auto":
        return request_format
    detected = detect_format(data)
    if detected == "unknown":
        raise HTTPException(
            status_code=400,
            detail="Could not auto-detect callgraph format. Please specify 'format' explicitly.",
        )
    return detected


def _canonical_language(language: str) -> str:
    try:
        return canonical_callgraph_language(language)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _resolve_language(request_language: str | None, format_type: str) -> str:
    """Resolve the callgraph language in its canonical spelling; only madge implies one."""
    language = request_language or _FORMAT_LANGUAGE_MAP.get(format_type)
    if not language:
        raise HTTPException(
            status_code=400,
            detail=f"'language' is required for '{format_type}' callgraph payloads",
        )
    return _canonical_language(language)


async def _resolve_scan_id(
    db: Any, project_id: str, pipeline_id: int | None, commit_hash: str | None
) -> tuple[str | None, bool]:
    """``(scan_id, exists)`` of the scan the CI run produced, only ever one of the authorized project's.

    An upload without the commit derives an id no ingest writes, so the run's newest scan stands in.
    """
    derived = deterministic_scan_id(project_id, pipeline_id, commit_hash)
    if derived is None:
        return None, False
    scans = ScanRepository(db).collection
    if await scans.find_one({"_id": derived, "project_id": project_id}, {"_id": 1}):
        return derived, True
    newest = await scans.find_one(
        {"project_id": project_id, "pipeline_id": pipeline_id}, {"_id": 1}, sort=[("created_at", -1)]
    )
    return (newest["_id"], True) if newest else (derived, False)


def _build_upsert_filter(project_id: str, language: str, scan_id: str | None) -> tuple[dict[str, Any], str]:
    """Build the MongoDB upsert filter and a context string for logging."""
    if scan_id:
        return {"project_id": project_id, "language": language, "scan_id": scan_id}, f"scan {scan_id} ({language})"
    return {
        "project_id": project_id,
        "language": language,
        "scan_id": None,
        "pipeline_id": None,
    }, f"project-level ({language})"


def _parse_callgraph(
    format_type: str, data: dict[str, Any], language: str
) -> tuple[list[ImportEntry], list[CallEdge], dict[str, ModuleUsage], list[str]]:
    """Parse callgraph data using the appropriate parser for the format."""
    parser = _FORMAT_PARSERS.get(format_type)
    if not parser:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format_type}")
    return parser(data, language)


@router.post("/{project_id}/callgraph", responses=RESP_AUTH_400)
async def upload_callgraph(
    project_id: str,
    request: CallgraphUploadRequest,
    db: DatabaseDep,
    _: CallgraphWriteDep,
) -> CallgraphUploadResponse:
    """Upload call graph data (madge or generic format) for reachability analysis."""
    callgraph_repo = CallgraphRepository(db)

    entry_count = callgraph_entry_count(request.data)
    if entry_count > CALLGRAPH_MAX_ENTRIES:
        raise HTTPException(
            status_code=413,
            detail=f"Callgraph too large: {entry_count} entries exceeds the limit of {CALLGRAPH_MAX_ENTRIES}",
        )

    format_type = _resolve_format(request.format, request.data)
    language = _resolve_language(request.language, format_type)

    warnings: list[str] = []
    try:
        imports, calls, module_usage, analyzed_modules = await asyncio.to_thread(
            _parse_callgraph, format_type, request.data, language
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to parse callgraph: %s", e)
        raise HTTPException(status_code=400, detail=f"Failed to parse callgraph: {e!s}") from e

    scan_id, scan_exists = await _resolve_scan_id(db, project_id, request.pipeline_id, request.commit_hash)
    if not scan_id:
        warnings.append(
            "No pipeline_id: the callgraph is stored project-level and is not used for reachability verdicts"
        )
    elif not scan_exists:
        warnings.append(f"No scan of pipeline {request.pipeline_id} exists yet; its analysis applies this callgraph")

    callgraph = Callgraph(
        project_id=project_id,
        pipeline_id=request.pipeline_id,
        branch=request.branch,
        commit_hash=request.commit_hash,
        scan_id=scan_id,
        language=language,
        tool=request.tool or format_type,
        tool_version=request.tool_version,
        imports=imports,
        calls=calls,
        module_usage=module_usage,
        analyzed_modules=analyzed_modules,
        source_files_analyzed=request.source_files_count or len({i.file for i in imports}),
        total_imports=len(imports),
        total_calls=len(calls),
        analysis_duration_ms=request.analysis_duration_ms,
    )

    upsert_filter, match_context = _build_upsert_filter(project_id, language, scan_id)

    callgraph_data = callgraph.model_dump(by_alias=True)
    insert_only = {"_id": callgraph_data.pop("_id"), "created_at": callgraph_data.pop("created_at")}
    await callgraph_repo.collection.update_one(
        upsert_filter,
        {"$set": callgraph_data, "$setOnInsert": insert_only},
        upsert=True,
    )

    logger.info(
        f"Uploaded callgraph for project {project_id} ({match_context}): "
        f"{len(imports)} imports, {len(calls)} calls, {len(module_usage)} modules, "
        f"{len(analyzed_modules)} analyzed modules"
    )

    if scan_exists:
        # Rescans created before this upload read the callgraph through their lineage root.
        pending_rescans = await ScanRepository(db).distinct(
            "_id", {"project_id": project_id, "original_scan_id": scan_id, "reachability_pending": True}
        )
        for target_scan_id in [scan_id, *pending_rescans]:
            try:
                reachability_result = await run_pending_reachability_for_scan(
                    scan_id=target_scan_id,
                    project_id=project_id,
                    db=db,
                )
                if reachability_result["findings_enriched"] > 0:
                    logger.info(
                        f"Processed pending reachability for scan {target_scan_id}: "
                        f"enriched {reachability_result['findings_enriched']} findings"
                    )
            except Exception as e:
                logger.warning(f"Failed to run pending reachability analysis: {e}")
                warnings.append(f"Reachability analysis deferred: {e!s}")

    return CallgraphUploadResponse(
        success=True,
        message=f"Callgraph uploaded successfully ({format_type} format)",
        project_id=project_id,
        imports_parsed=len(imports),
        calls_parsed=len(calls),
        modules_detected=len(module_usage),
        analyzed_modules_count=len(analyzed_modules),
        warnings=warnings,
    )


@router.get("/{project_id}/callgraph", responses=RESP_AUTH_404)
async def get_callgraph(
    project_id: str,
    db: DatabaseDep,
    current_user: CurrentUserDep,
    language: str | None = None,
) -> CallgraphResponse:
    """Get the current callgraph for a project, optionally filtered by language."""
    await check_callgraph_access(project_id, current_user, db)

    callgraph_repo = CallgraphRepository(db)
    query: dict[str, Any] = {"project_id": project_id}
    if language:
        query["language"] = _canonical_language(language)
    callgraph = await callgraph_repo.find_one(query)
    if not callgraph:
        raise HTTPException(status_code=404, detail="No callgraph found for this project")

    data = callgraph.model_dump(by_alias=False, exclude={"id"})
    return CallgraphResponse(**data)


@router.get("/{project_id}/callgraph/modules", responses=RESP_AUTH_404)
async def get_module_usage(
    project_id: str,
    db: DatabaseDep,
    current_user: CurrentUserDep,
    language: str | None = None,
) -> ModuleUsageResponse:
    """Get external module usage (import counts and locations) from the callgraph, optionally filtered by language."""
    await check_callgraph_access(project_id, current_user, db)

    callgraph_repo = CallgraphRepository(db)
    query: dict[str, Any] = {"project_id": project_id}
    if language:
        query["language"] = _canonical_language(language)
    callgraph = await callgraph_repo.find_one(query)
    if not callgraph:
        raise HTTPException(status_code=404, detail="No callgraph found")

    module_usage = callgraph.module_usage or {}

    sorted_modules = sorted(
        module_usage.items(),
        key=lambda x: x[1].import_count + x[1].call_count,
        reverse=True,
    )

    return ModuleUsageResponse(
        project_id=project_id,
        language=callgraph.language,
        modules=[{"name": k, "module": k, **v.model_dump()} for k, v in sorted_modules],
    )


@router.delete("/{project_id}/callgraph", responses=RESP_AUTH_404)
async def delete_callgraph(
    project_id: str,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> DeleteCallgraphResponse:
    """Delete the callgraph for a project."""
    await check_callgraph_access(project_id, current_user, db, require_write=True)

    callgraph_repo = CallgraphRepository(db)
    deleted_count = await callgraph_repo.delete_by_project(project_id)

    if deleted_count == 0:
        raise HTTPException(status_code=404, detail="No callgraph found")

    return DeleteCallgraphResponse(success=True, message="Callgraph deleted")
