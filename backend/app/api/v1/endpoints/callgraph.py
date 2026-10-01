"""Endpoints for uploading and querying call graph data for reachability analysis."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

from app.api.deps import CurrentUserDep, DatabaseDep, ProjectWriteDep
from app.api.router import CustomAPIRouter
from app.api.v1.helpers.callgraph import (
    ParsedCallgraph,
    detect_format,
    parse_generic_format,
    parse_madge_format,
)
from app.api.v1.helpers.projects import check_project_access
from app.api.v1.helpers.request_body import read_json_body
from app.api.v1.helpers.responses import RESP_AUTH_400, RESP_AUTH_404
from app.core.constants import PROJECT_ROLE_EDITOR, SCANS_TIP_SORT
from app.models.callgraph import Callgraph
from app.repositories.callgraphs import CallgraphRepository
from app.repositories.scans import ScanRepository
from app.schemas.callgraph import (
    CallgraphResponse,
    CallgraphUploadRequest,
    CallgraphUploadResponse,
    DeleteCallgraphResponse,
    ModuleUsageItem,
    ModuleUsageResponse,
)
from app.services.component_identity import canonical_callgraph_language
from app.services.gridfs_maintenance import upload_gridfs_json
from app.services.reachability_enrichment import run_pending_reachability_for_scan
from app.services.scan_manager import deterministic_scan_id

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


_FORMAT_LANGUAGE_MAP = {"madge": "javascript"}

_FORMAT_PARSERS = {
    "madge": parse_madge_format,
    "generic": parse_generic_format,
}

_GRAPH_FIELDS = ("module_usage", "analyzed_modules")
_RESPONSE_PROJECTION = dict.fromkeys((*CallgraphResponse.model_fields, "graph_gridfs_id"), 1)


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
    """``(scan_id, exists)`` of the CI run's scan in the authorized project; its newest scan when the derived id has none."""
    derived = deterministic_scan_id(project_id, pipeline_id, commit_hash)
    if derived is None:
        return None, False
    scan_repo = ScanRepository(db)
    scan = await scan_repo.get_minimal_by_id(derived)
    if scan and scan.project_id == project_id:
        return derived, True
    newest = await scan_repo.find_one({"project_id": project_id, "pipeline_id": pipeline_id}, sort=SCANS_TIP_SORT)
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


def _parse_callgraph(format_type: str, data: dict[str, Any], language: str) -> ParsedCallgraph:
    """Parse callgraph data using the appropriate parser for the format."""
    parser = _FORMAT_PARSERS.get(format_type)
    if not parser:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format_type}")
    return parser(data, language)


@router.post("/{project_id}/callgraph", responses=RESP_AUTH_400)
async def upload_callgraph(
    project_id: str,
    request: Request,
    db: DatabaseDep,
    _: ProjectWriteDep,
) -> CallgraphUploadResponse:
    """Upload call graph data (madge or generic format) for reachability analysis."""
    upload = await read_json_body(request, CallgraphUploadRequest)
    callgraph_repo = CallgraphRepository(db)
    format_type = _resolve_format(upload.format, upload.data)
    language = _resolve_language(upload.language, format_type)

    warnings: list[str] = []
    try:
        parsed = await asyncio.to_thread(_parse_callgraph, format_type, upload.data, language)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to parse callgraph: %s", e)
        raise HTTPException(status_code=400, detail=f"Failed to parse callgraph: {e!s}") from e

    scan_id, scan_exists = await _resolve_scan_id(db, project_id, upload.pipeline_id, upload.commit_hash)
    if not scan_id:
        warnings.append(
            "No pipeline_id: the callgraph is stored project-level and is not used for reachability verdicts"
        )
    elif not scan_exists:
        warnings.append(f"No scan of pipeline {upload.pipeline_id} exists yet; its analysis applies this callgraph")

    callgraph = Callgraph(
        project_id=project_id,
        pipeline_id=upload.pipeline_id,
        branch=upload.branch,
        commit_hash=upload.commit_hash,
        scan_id=scan_id,
        language=language,
        tool=upload.tool or format_type,
        tool_version=upload.tool_version,
        module_usage=parsed.module_usage,
        analyzed_modules=parsed.analyzed_modules,
        source_files_analyzed=upload.source_files_count or parsed.source_files,
        total_imports=parsed.total_imports,
        total_calls=parsed.total_calls,
        analysis_duration_ms=upload.analysis_duration_ms,
    )

    upsert_filter, match_context = _build_upsert_filter(project_id, language, scan_id)

    callgraph_data = callgraph.model_dump(by_alias=True)
    uploaded_at = callgraph_data.pop("created_at")
    insert_only = {"_id": callgraph_data.pop("_id"), "created_at": uploaded_at}
    graph = {field: callgraph_data.pop(field) for field in _GRAPH_FIELDS}
    scan_repo = ScanRepository(db)
    if scan_exists:
        await scan_repo.update_raw(scan_id, {"$set": {"updated_at": datetime.now(timezone.utc)}})
    graph_gridfs_id = await upload_gridfs_json(db, f"callgraph-{project_id}-{language}.json", graph)
    await callgraph_repo.collection.update_one(
        upsert_filter,
        {
            "$set": {**callgraph_data, "graph_gridfs_id": graph_gridfs_id, "updated_at": uploaded_at},
            "$unset": dict.fromkeys(_GRAPH_FIELDS, ""),
            "$setOnInsert": insert_only,
        },
        upsert=True,
    )

    logger.info(
        f"Uploaded callgraph for project {project_id} ({match_context}): "
        f"{parsed.total_imports} imports, {parsed.total_calls} calls, {len(parsed.module_usage)} modules, "
        f"{len(parsed.analyzed_modules)} analyzed modules"
    )

    if scan_exists:
        # Rescans created before this upload read the callgraph through the build they re-analyse.
        pending_rescans = await scan_repo.distinct(
            "_id", {"project_id": project_id, "original_scan_id": scan_id, "reachability_pending": True}
        )
        for target_scan_id in [scan_id, *pending_rescans]:
            written = {"reachability_pending": True, "updated_at": datetime.now(timezone.utc)}
            await scan_repo.update_raw(target_scan_id, {"$set": written})
            try:
                dropped = await run_pending_reachability_for_scan(target_scan_id, project_id, db)
            except Exception as e:
                logger.exception("Failed to run pending reachability analysis for scan %s", target_scan_id)
                warnings.append(f"Reachability analysis deferred: {e!s}")
                continue
            if dropped:
                warnings.append(f"{dropped} findings beyond the per-run cap were left without a reachability verdict")

    return CallgraphUploadResponse(
        success=True,
        message=f"Callgraph uploaded successfully ({format_type} format)",
        project_id=project_id,
        imports_parsed=parsed.total_imports,
        calls_parsed=parsed.total_calls,
        modules_detected=len(parsed.module_usage),
        analyzed_modules_count=len(parsed.analyzed_modules),
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
    await check_project_access(project_id, current_user, db)

    callgraph_repo = CallgraphRepository(db)
    query: dict[str, Any] = {"project_id": project_id}
    if language:
        query["language"] = _canonical_language(language)
    callgraph = await callgraph_repo.find_one_raw(query, _RESPONSE_PROJECTION)
    if not callgraph:
        raise HTTPException(status_code=404, detail="No callgraph found for this project")

    return CallgraphResponse(**await callgraph_repo.load_graph(callgraph))


@router.get("/{project_id}/callgraph/modules", responses=RESP_AUTH_404)
async def get_module_usage(
    project_id: str,
    db: DatabaseDep,
    current_user: CurrentUserDep,
    language: str | None = None,
) -> ModuleUsageResponse:
    """Get external module usage (import counts and locations) from the callgraph, optionally filtered by language."""
    await check_project_access(project_id, current_user, db)

    callgraph_repo = CallgraphRepository(db)
    query: dict[str, Any] = {"project_id": project_id}
    if language:
        query["language"] = _canonical_language(language)
    callgraph = await callgraph_repo.find_one_raw(query, {"module_usage": 1, "language": 1, "graph_gridfs_id": 1})
    if not callgraph:
        raise HTTPException(status_code=404, detail="No callgraph found")
    await callgraph_repo.load_graph(callgraph)

    sorted_modules = sorted(
        (ModuleUsageItem(name=key, **usage) for key, usage in callgraph["module_usage"].items()),
        key=lambda item: item.import_count + item.call_count,
        reverse=True,
    )

    return ModuleUsageResponse(project_id=project_id, language=callgraph["language"], modules=sorted_modules)


@router.delete("/{project_id}/callgraph", responses=RESP_AUTH_404)
async def delete_callgraph(
    project_id: str,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> DeleteCallgraphResponse:
    """Delete the callgraph for a project."""
    await check_project_access(project_id, current_user, db, required_role=PROJECT_ROLE_EDITOR)

    callgraph_repo = CallgraphRepository(db)
    deleted_count = await callgraph_repo.delete_by_project(project_id)

    if deleted_count == 0:
        raise HTTPException(status_code=404, detail="No callgraph found")

    return DeleteCallgraphResponse(success=True, message="Callgraph deleted")
