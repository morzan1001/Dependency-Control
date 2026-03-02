"""
Callgraph API Endpoints

Provides endpoints for uploading and querying call graph data
for reachability analysis.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException

from app.api.router import CustomAPIRouter
from app.api.v1.helpers.responses import RESP_AUTH_400, RESP_AUTH_404

from app.api.deps import CurrentUserDep, DatabaseDep
from app.api.v1.helpers.callgraph import (
    check_callgraph_access,
    detect_format,
    parse_generic_format,
    parse_madge_format,
    parse_pyan_format,
)
from app.models.callgraph import CallEdge, ImportEntry, ModuleUsage
from app.models.callgraph import Callgraph
from app.repositories import CallgraphRepository
from app.schemas.callgraph import (
    CallgraphResponse,
    CallgraphUploadRequest,
    CallgraphUploadResponse,
    DeleteCallgraphResponse,
    ModuleUsageResponse,
)
from app.services.reachability_enrichment import run_pending_reachability_for_scan

router = CustomAPIRouter()
logger = logging.getLogger(__name__)


_FORMAT_LANGUAGE_MAP = {
    "madge": "javascript",
    "pyan": "python",
    "go-callvis": "go",
}

_FORMAT_PARSERS = {
    "madge": parse_madge_format,
    "pyan": parse_pyan_format,
    "go-callvis": parse_pyan_format,
    "generic": parse_generic_format,
}


def _resolve_format(request_format: str, data: Dict[str, Any]) -> str:
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


def _resolve_scan_id(
    request_scan_id: Optional[str], project_id: str, pipeline_id: Optional[int], commit_hash: Optional[str]
) -> Optional[str]:
    """Resolve the scan_id from request context."""
    if request_scan_id:
        return request_scan_id
    if not pipeline_id:
        return None
    if commit_hash:
        scan_id_seed = f"{project_id}-{pipeline_id}-{commit_hash}"
    else:
        scan_id_seed = f"{project_id}-{pipeline_id}"
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))


def _build_upsert_filter(
    project_id: str, language: str, scan_id: Optional[str], pipeline_id: Optional[int], warnings: List[str]
) -> Tuple[Dict[str, Any], str]:
    """Build the MongoDB upsert filter and a context string for logging."""
    if scan_id:
        return {"project_id": project_id, "language": language, "scan_id": scan_id}, f"scan {scan_id} ({language})"
    if pipeline_id:
        return {"project_id": project_id, "language": language, "pipeline_id": pipeline_id}, f"pipeline {pipeline_id} ({language})"
    warnings.append("No pipeline_id or scan_id provided - callgraph may not match scans correctly")
    return {"project_id": project_id, "language": language, "scan_id": None, "pipeline_id": None}, f"project-level ({language})"


def _parse_callgraph(
    format_type: str, data: Dict[str, Any], language: str
) -> Tuple[List[ImportEntry], List[CallEdge], Dict[str, ModuleUsage]]:
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
    current_user: CurrentUserDep,
) -> CallgraphUploadResponse:
    """
    Upload call graph data for a project.

    Supports multiple formats:
    - **madge**: JavaScript/TypeScript dependency graph
    - **pyan**: Python call graph
    - **go-callvis**: Go call graph
    - **generic**: Universal format for any language

    The callgraph is used for reachability analysis to determine
    if vulnerable code paths are actually used in the project.
    """
    await check_callgraph_access(project_id, current_user, db, require_write=True)

    callgraph_repo = CallgraphRepository(db)

    format_type = _resolve_format(request.format, request.data)
    language = request.language or _FORMAT_LANGUAGE_MAP.get(format_type, "unknown")

    warnings: List[str] = []
    try:
        imports, calls, module_usage = _parse_callgraph(format_type, request.data, language)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to parse callgraph: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to parse callgraph: {str(e)}")

    scan_id = _resolve_scan_id(request.scan_id, project_id, request.pipeline_id, request.commit_hash)
    if scan_id and not request.scan_id:
        logger.debug(f"Generated deterministic scan_id {scan_id} from pipeline_id {request.pipeline_id}")

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
        module_usage={k: v.model_dump() for k, v in module_usage.items()},
        source_files_analyzed=request.source_files_count or len({i.file for i in imports}),
        total_imports=len(imports),
        total_calls=len(calls),
        analysis_duration_ms=request.analysis_duration_ms,
    )

    upsert_filter, match_context = _build_upsert_filter(project_id, language, scan_id, request.pipeline_id, warnings)

    callgraph_data = callgraph.model_dump(by_alias=True)
    callgraph_id = callgraph_data.pop("_id")
    await callgraph_repo.collection.update_one(
        upsert_filter,
        {"$set": callgraph_data, "$setOnInsert": {"_id": callgraph_id}},
        upsert=True,
    )

    logger.info(
        f"Uploaded callgraph for project {project_id} ({match_context}): "
        f"{len(imports)} imports, {len(calls)} calls, {len(module_usage)} modules"
    )

    # Check for pending reachability analysis on this scan
    if scan_id:
        try:
            reachability_result = await run_pending_reachability_for_scan(
                scan_id=scan_id,
                project_id=project_id,
                db=db,
            )
            if reachability_result["findings_enriched"] > 0:
                logger.info(
                    f"Processed pending reachability for scan {scan_id}: "
                    f"enriched {reachability_result['findings_enriched']} findings"
                )
        except Exception as e:
            logger.warning(f"Failed to run pending reachability analysis: {e}")
            warnings.append(f"Reachability analysis deferred: {str(e)}")

    return CallgraphUploadResponse(
        success=True,
        message=f"Callgraph uploaded successfully ({format_type} format)",
        project_id=project_id,
        imports_parsed=len(imports),
        calls_parsed=len(calls),
        modules_detected=len(module_usage),
        warnings=warnings,
    )


@router.get("/{project_id}/callgraph", responses=RESP_AUTH_404)
async def get_callgraph(
    project_id: str,
    db: DatabaseDep,
    current_user: CurrentUserDep,
    language: Optional[str] = None,
) -> CallgraphResponse:
    """
    Get the current callgraph for a project.

    Optionally filter by language (e.g. ?language=python).
    """
    await check_callgraph_access(project_id, current_user, db)

    callgraph_repo = CallgraphRepository(db)
    query: Dict[str, Any] = {"project_id": project_id}
    if language:
        query["language"] = language
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
    language: Optional[str] = None,
) -> ModuleUsageResponse:
    """
    Get module usage summary from the callgraph.

    Returns a list of external modules used in the project,
    with import counts and locations. Optionally filter by language.
    """
    await check_callgraph_access(project_id, current_user, db)

    callgraph_repo = CallgraphRepository(db)
    query: Dict[str, Any] = {"project_id": project_id}
    if language:
        query["language"] = language
    callgraph = await callgraph_repo.find_one(query)
    if not callgraph:
        raise HTTPException(status_code=404, detail="No callgraph found")

    module_usage = callgraph.module_usage or {}

    # Sort by import count
    sorted_modules = sorted(
        module_usage.items(),
        key=lambda x: getattr(x[1], "import_count", 0) + getattr(x[1], "call_count", 0),
        reverse=True,
    )

    return ModuleUsageResponse(
        project_id=project_id,
        language=callgraph.language,
        modules=[{"name": k, "module": k, **v} for k, v in sorted_modules],
    )


@router.delete("/{project_id}/callgraph", responses=RESP_AUTH_404)
async def delete_callgraph(
    project_id: str,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> DeleteCallgraphResponse:
    """
    Delete the callgraph for a project.
    """
    await check_callgraph_access(project_id, current_user, db, require_write=True)

    callgraph_repo = CallgraphRepository(db)
    deleted_count = await callgraph_repo.delete_by_project(project_id)

    if deleted_count == 0:
        raise HTTPException(status_code=404, detail="No callgraph found")

    return DeleteCallgraphResponse(success=True, message="Callgraph deleted")
