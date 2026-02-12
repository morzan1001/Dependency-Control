"""
Callgraph API Endpoints

Provides endpoints for uploading and querying call graph data
for reachability analysis.
"""

import logging
from typing import Any, Dict

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


@router.post("/{project_id}/callgraph", response_model=CallgraphUploadResponse, responses={**RESP_AUTH_400})
async def upload_callgraph(
    project_id: str,
    request: CallgraphUploadRequest,
    db: DatabaseDep,
    current_user: CurrentUserDep,
):
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
    # Verify project exists and user has write access
    await check_callgraph_access(project_id, current_user, db, require_write=True)

    callgraph_repo = CallgraphRepository(db)

    # Detect format
    format_type = request.format
    if format_type == "auto":
        format_type = detect_format(request.data)
        if format_type == "unknown":
            raise HTTPException(
                status_code=400,
                detail="Could not auto-detect callgraph format. Please specify 'format' explicitly.",
            )

    # Determine language
    language = request.language
    if not language:
        language_map = {
            "madge": "javascript",
            "pyan": "python",
            "go-callvis": "go",
        }
        language = language_map.get(format_type, "unknown")

    # Parse based on format
    warnings = []
    try:
        if format_type == "madge":
            imports, calls, module_usage = parse_madge_format(request.data, language)
        elif format_type == "pyan":
            imports, calls, module_usage = parse_pyan_format(request.data, language)
        elif format_type == "go-callvis":
            # Similar to pyan, use same parser with slight adjustments
            imports, calls, module_usage = parse_pyan_format(request.data, language)
        elif format_type == "generic":
            imports, calls, module_usage = parse_generic_format(request.data, language)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format_type}")
    except Exception as e:
        logger.error(f"Failed to parse callgraph: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to parse callgraph: {str(e)}")

    import uuid

    scan_id = request.scan_id
    if not scan_id and request.pipeline_id:
        # This ensures callgraph is linked to the correct scan
        if request.commit_hash:
            # Deterministic: Same commit + pipeline = same scan
            scan_id_seed = f"{project_id}-{request.pipeline_id}-{request.commit_hash}"
            scan_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))
        else:
            # No commit_hash: Use pipeline_id only (less precise)
            scan_id_seed = f"{project_id}-{request.pipeline_id}"
            scan_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, scan_id_seed))

        logger.debug(f"Generated deterministic scan_id {scan_id} from pipeline_id {request.pipeline_id}")

    callgraph = Callgraph(
        project_id=project_id,
        pipeline_id=request.pipeline_id,
        branch=request.branch,
        commit_hash=request.commit_hash,
        scan_id=scan_id,  # Link to the resolved scan
        language=language,
        tool=request.tool or format_type,
        tool_version=request.tool_version,
        imports=imports,
        calls=calls,
        module_usage={k: v.model_dump() for k, v in module_usage.items()},
        source_files_analyzed=request.source_files_count or len(set(i.file for i in imports)),
        total_imports=len(imports),
        total_calls=len(calls),
        analysis_duration_ms=request.analysis_duration_ms,
    )

    # Upsert callgraph - keyed by scan_id if available, otherwise by pipeline_id
    # This ensures one callgraph per scan/pipeline
    if scan_id:
        upsert_filter: Dict[str, Any] = {"project_id": project_id, "scan_id": scan_id}
        match_context = f"scan {scan_id}"
    elif request.pipeline_id:
        upsert_filter = {"project_id": project_id, "pipeline_id": request.pipeline_id}
        match_context = f"pipeline {request.pipeline_id}"
    else:
        # No scan_id or pipeline_id - this is unusual, warn the user
        upsert_filter = {"project_id": project_id, "scan_id": None, "pipeline_id": None}
        match_context = "project-level (no pipeline context)"
        warnings.append("No pipeline_id or scan_id provided - callgraph may not match scans correctly")

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


@router.get("/{project_id}/callgraph", responses={**RESP_AUTH_404})
async def get_callgraph(
    project_id: str,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> CallgraphResponse:
    """
    Get the current callgraph for a project.
    """
    await check_callgraph_access(project_id, current_user, db)

    callgraph_repo = CallgraphRepository(db)
    callgraph = await callgraph_repo.get_by_project(project_id)
    if not callgraph:
        raise HTTPException(status_code=404, detail="No callgraph found for this project")

    # Remove MongoDB _id
    callgraph.pop("_id", None)

    return CallgraphResponse(**callgraph)


@router.get("/{project_id}/callgraph/modules", responses={**RESP_AUTH_404})
async def get_module_usage(
    project_id: str,
    db: DatabaseDep,
    current_user: CurrentUserDep,
) -> ModuleUsageResponse:
    """
    Get module usage summary from the callgraph.

    Returns a list of external modules used in the project,
    with import counts and locations.
    """
    await check_callgraph_access(project_id, current_user, db)

    callgraph_repo = CallgraphRepository(db)
    callgraph = await callgraph_repo.get_by_project(project_id)
    if not callgraph:
        raise HTTPException(status_code=404, detail="No callgraph found")

    module_usage = callgraph.get("module_usage", {})

    # Sort by import count
    sorted_modules = sorted(
        module_usage.items(),
        key=lambda x: x[1].get("import_count", 0) + x[1].get("call_count", 0),
        reverse=True,
    )

    return ModuleUsageResponse(
        project_id=project_id,
        language=callgraph.get("language"),
        modules=[{"name": k, "module": k, **v} for k, v in sorted_modules],
    )


@router.delete("/{project_id}/callgraph", responses={**RESP_AUTH_404})
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
