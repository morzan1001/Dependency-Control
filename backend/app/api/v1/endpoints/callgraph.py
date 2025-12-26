"""
Callgraph API Endpoints

Provides endpoints for uploading and querying call graph data
for reachability analysis.
"""

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import get_current_user
from app.db.mongodb import get_database
from app.models.callgraph import CallEdge, Callgraph, ImportEntry, ModuleUsage
from app.schemas.callgraph import (CallgraphUploadRequest,
                                   CallgraphUploadResponse)
from app.services.reachability_enrichment import \
    run_pending_reachability_for_scan

router = APIRouter()
logger = logging.getLogger(__name__)


def normalize_module_name(module: str, language: str) -> str:
    """
    Normalize a module/package name for consistent matching.

    Examples:
    - "./utils" -> relative path (keep as-is for now)
    - "lodash" -> "lodash"
    - "@org/pkg" -> "@org/pkg"
    - "lodash/get" -> "lodash"
    """
    if not module:
        return module

    # Remove relative path prefixes for external module detection
    if module.startswith("./") or module.startswith("../"):
        return module  # Keep relative paths as-is

    # For scoped packages (@org/pkg), keep full name
    if module.startswith("@"):
        parts = module.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return module

    # For regular packages, extract base package name
    if "/" in module:
        return module.split("/")[0]

    return module


def parse_madge_format(
    data: Dict[str, Any], language: str
) -> tuple[List[ImportEntry], List[CallEdge], Dict[str, ModuleUsage]]:
    """
    Parse madge JSON output format.

    Madge format:
    {
        "src/index.js": ["./utils", "lodash", "axios"],
        "src/utils.js": ["lodash/get", "./helpers"]
    }
    """
    imports = []
    module_usage: Dict[str, ModuleUsage] = {}

    for file_path, dependencies in data.items():
        if not isinstance(dependencies, list):
            continue

        for dep in dependencies:
            if not isinstance(dep, str):
                continue

            # Create import entry
            imports.append(
                ImportEntry(
                    module=dep,
                    file=file_path,
                    line=0,  # Madge doesn't provide line numbers
                    imported_symbols=[],
                    is_dynamic=False,
                )
            )

            # Aggregate module usage (only for external modules)
            if not dep.startswith("./") and not dep.startswith("../"):
                base_module = normalize_module_name(dep, language)
                if base_module not in module_usage:
                    module_usage[base_module] = ModuleUsage(
                        module=base_module,
                        import_count=0,
                        call_count=0,
                        import_locations=[],
                        used_symbols=[],
                    )
                module_usage[base_module].import_count += 1
                if file_path not in module_usage[base_module].import_locations:
                    module_usage[base_module].import_locations.append(file_path)

    # Madge doesn't provide call edges, only imports
    return imports, [], module_usage


def parse_pyan_format(
    data: Dict[str, Any], language: str
) -> tuple[List[ImportEntry], List[CallEdge], Dict[str, ModuleUsage]]:
    """
    Parse pyan JSON output format.

    Pyan format:
    {
        "nodes": [{"name": "module.func", "type": "function", "file": "...", "line": 10}],
        "edges": [{"source": "module.func", "target": "other.func", "type": "calls"}]
    }
    """
    imports = []
    calls = []
    module_usage: Dict[str, ModuleUsage] = {}

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    # Build node lookup
    node_info = {}
    for node in nodes:
        name = node.get("name", "")
        node_info[name] = {
            "file": node.get("file", ""),
            "line": node.get("line", 0),
            "type": node.get("type", ""),
        }

    # Process edges as calls
    for edge in edges:
        source = edge.get("source", "")
        target = edge.get("target", "")
        edge_type = edge.get("type", "calls")

        if edge_type == "calls":
            source_info = node_info.get(source, {})
            calls.append(
                CallEdge(
                    caller=source,
                    callee=target,
                    file=source_info.get("file", ""),
                    line=source_info.get("line", 0),
                    call_type="direct",
                )
            )

            # Extract module from target
            if "." in target:
                module = target.rsplit(".", 1)[0]
                base_module = normalize_module_name(module, language)
                if base_module not in module_usage:
                    module_usage[base_module] = ModuleUsage(
                        module=base_module,
                        import_count=0,
                        call_count=0,
                        import_locations=[],
                        used_symbols=[],
                    )
                module_usage[base_module].call_count += 1

                # Track used symbol
                symbol = target.rsplit(".", 1)[-1]
                if symbol not in module_usage[base_module].used_symbols:
                    module_usage[base_module].used_symbols.append(symbol)

    return imports, calls, module_usage


def parse_generic_format(
    data: Dict[str, Any], language: str
) -> tuple[List[ImportEntry], List[CallEdge], Dict[str, ModuleUsage]]:
    """
    Parse generic callgraph format.
    """
    imports = []
    calls = []
    module_usage: Dict[str, ModuleUsage] = {}

    # Parse imports
    for imp in data.get("imports", []):
        imports.append(
            ImportEntry(
                module=imp.get("module", ""),
                file=imp.get("file", ""),
                line=imp.get("line", 0),
                imported_symbols=imp.get("symbols", []),
                is_dynamic=False,
            )
        )

        # Aggregate
        module = imp.get("module", "")
        if module and not module.startswith("./") and not module.startswith("../"):
            base_module = normalize_module_name(module, language)
            if base_module not in module_usage:
                module_usage[base_module] = ModuleUsage(
                    module=base_module,
                    import_count=0,
                    call_count=0,
                    import_locations=[],
                    used_symbols=[],
                )
            module_usage[base_module].import_count += 1
            file_path = imp.get("file", "")
            if file_path not in module_usage[base_module].import_locations:
                module_usage[base_module].import_locations.append(file_path)
            for sym in imp.get("symbols", []):
                if sym not in module_usage[base_module].used_symbols:
                    module_usage[base_module].used_symbols.append(sym)

    # Parse calls
    for call in data.get("calls", []):
        calls.append(
            CallEdge(
                caller=f"{call.get('caller_file', '')}:{call.get('caller_function', '')}",
                callee=f"{call.get('callee_module', '')}:{call.get('callee_function', '')}",
                file=call.get("caller_file", ""),
                line=call.get("line", 0),
                call_type="direct",
            )
        )

        # Aggregate
        module = call.get("callee_module", "")
        if module:
            base_module = normalize_module_name(module, language)
            if base_module not in module_usage:
                module_usage[base_module] = ModuleUsage(
                    module=base_module,
                    import_count=0,
                    call_count=0,
                    import_locations=[],
                    used_symbols=[],
                )
            module_usage[base_module].call_count += 1
            func = call.get("callee_function", "")
            if func and func not in module_usage[base_module].used_symbols:
                module_usage[base_module].used_symbols.append(func)

    return imports, calls, module_usage


def detect_format(data: Dict[str, Any]) -> str:
    """Auto-detect callgraph format from data structure."""

    # Check for pyan/go-callvis format (has nodes and edges)
    if "nodes" in data and "edges" in data:
        # Check if it's pyan or go-callvis
        nodes = data.get("nodes", [])
        if nodes and isinstance(nodes[0], dict):
            if "package" in nodes[0]:
                return "go-callvis"
            return "pyan"

    # Check for generic format
    if "imports" in data or "calls" in data:
        return "generic"

    # Check for madge format (dict of file -> dependencies)
    if all(isinstance(v, list) for v in data.values() if v):
        return "madge"

    return "unknown"


@router.post("/{project_id}/callgraph", response_model=CallgraphUploadResponse)
async def upload_callgraph(
    project_id: str,
    request: CallgraphUploadRequest,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
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
    # Verify project exists and user has access
    project = await db.projects.find_one({"_id": project_id})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check access
    if project.get("owner_id") != current_user["_id"]:
        team_ids = project.get("team_ids", [])
        user_teams = await db.teams.find(
            {"_id": {"$in": team_ids}, "members.user_id": current_user["_id"]}
        ).to_list(None)
        if not user_teams and not current_user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Access denied")

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
            raise HTTPException(
                status_code=400, detail=f"Unsupported format: {format_type}"
            )
    except Exception as e:
        logger.error(f"Failed to parse callgraph: {e}")
        raise HTTPException(
            status_code=400, detail=f"Failed to parse callgraph: {str(e)}"
        )

    # Create callgraph document
    # First, resolve scan_id if only pipeline_id is provided
    scan_id = request.scan_id
    if not scan_id and request.pipeline_id:
        # Find the scan for this pipeline (consistent with other ingest endpoints)
        existing_scan = await db.scans.find_one(
            {
                "project_id": project_id,
                "pipeline_id": request.pipeline_id,
            }
        )
        if existing_scan:
            scan_id = existing_scan["_id"]
            logger.debug(
                f"Resolved scan_id {scan_id} from pipeline_id {request.pipeline_id}"
            )

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
        source_files_analyzed=request.source_files_count
        or len(set(i.file for i in imports)),
        total_imports=len(imports),
        total_calls=len(calls),
        analysis_duration_ms=request.analysis_duration_ms,
    )

    # Upsert callgraph - keyed by scan_id if available, otherwise by pipeline_id
    # This ensures one callgraph per scan/pipeline
    if scan_id:
        upsert_filter = {"project_id": project_id, "scan_id": scan_id}
        match_context = f"scan {scan_id}"
    elif request.pipeline_id:
        upsert_filter = {"project_id": project_id, "pipeline_id": request.pipeline_id}
        match_context = f"pipeline {request.pipeline_id}"
    else:
        # No scan_id or pipeline_id - this is unusual, warn the user
        upsert_filter = {"project_id": project_id, "scan_id": None, "pipeline_id": None}
        match_context = "project-level (no pipeline context)"
        warnings.append(
            "No pipeline_id or scan_id provided - callgraph may not match scans correctly"
        )

    await db.callgraphs.update_one(
        upsert_filter,
        {"$set": callgraph.model_dump()},
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


@router.get("/{project_id}/callgraph")
async def get_callgraph(
    project_id: str,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    """
    Get the current callgraph for a project.
    """
    # Verify project access
    project = await db.projects.find_one({"_id": project_id})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    callgraph = await db.callgraphs.find_one({"project_id": project_id})
    if not callgraph:
        raise HTTPException(
            status_code=404, detail="No callgraph found for this project"
        )

    # Remove MongoDB _id
    callgraph.pop("_id", None)

    return callgraph


@router.get("/{project_id}/callgraph/modules")
async def get_module_usage(
    project_id: str,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    """
    Get module usage summary from the callgraph.

    Returns a list of external modules used in the project,
    with import counts and locations.
    """
    callgraph = await db.callgraphs.find_one({"project_id": project_id})
    if not callgraph:
        raise HTTPException(status_code=404, detail="No callgraph found")

    module_usage = callgraph.get("module_usage", {})

    # Sort by import count
    sorted_modules = sorted(
        module_usage.items(),
        key=lambda x: x[1].get("import_count", 0) + x[1].get("call_count", 0),
        reverse=True,
    )

    return {
        "project_id": project_id,
        "language": callgraph.get("language"),
        "modules": [{"name": k, **v} for k, v in sorted_modules],
    }


@router.delete("/{project_id}/callgraph")
async def delete_callgraph(
    project_id: str,
    db=Depends(get_database),
    current_user=Depends(get_current_user),
):
    """
    Delete the callgraph for a project.
    """
    result = await db.callgraphs.delete_one({"project_id": project_id})

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="No callgraph found")

    return {"success": True, "message": "Callgraph deleted"}
