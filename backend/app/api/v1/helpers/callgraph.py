"""Helper functions for callgraph endpoints."""

from typing import Any, Dict, List

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.core.permissions import Permissions, has_permission
from app.models.callgraph import CallEdge, ImportEntry, ModuleUsage
from app.models.user import User
from app.repositories import ProjectRepository, TeamRepository


def _has_global_permission(user: User, require_write: bool) -> bool:
    """Check if user has global permissions for callgraph access."""
    if require_write:
        return has_permission(user.permissions, Permissions.PROJECT_UPDATE)
    return has_permission(user.permissions, [Permissions.PROJECT_READ_ALL, Permissions.PROJECT_UPDATE])


def _is_member(members: List[Dict[str, Any]], user_id: str) -> bool:
    """Check if user_id appears in a members list."""
    return any(member.get("user_id") == user_id for member in members)


async def check_callgraph_access(
    project_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    require_write: bool = False,
) -> Dict[str, Any]:
    """Verify user has access to the project's callgraph and return the project document.

    require_write=True demands write permission (for upload/delete).
    Raises 404 if the project is not found, 403 if access is denied.
    """
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    project = await project_repo.get_raw_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    user_id = str(user.id)

    if _has_global_permission(user, require_write):
        return project

    team_id = project.get("team_id")
    if team_id:
        team = await team_repo.get_raw_by_id(team_id)
        if team and _is_member(team.get("members", []), user_id):
            return project

    if _is_member(project.get("members", []), user_id):
        return project

    raise HTTPException(status_code=403, detail="Access denied")


def normalize_module_name(module: str, _language: str) -> str:
    """Normalize a module/package name for consistent matching.

    Relative paths are kept as-is; scoped packages keep ``@org/pkg``; regular
    packages are reduced to their base name (``lodash/get`` -> ``lodash``).
    """
    if not module:
        return module

    if module.startswith("./") or module.startswith("../"):
        return module

    if module.startswith("@"):
        parts = module.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return module

    if "/" in module:
        return module.split("/")[0]

    return module


def _is_external_module(dep: str) -> bool:
    """Check if a dependency is an external module (not a relative path)."""
    return not dep.startswith("./") and not dep.startswith("../")


def _get_or_create_module_usage(module_usage: Dict[str, ModuleUsage], base_module: str) -> ModuleUsage:
    """Get existing or create new ModuleUsage entry."""
    if base_module not in module_usage:
        module_usage[base_module] = ModuleUsage(
            module=base_module,
            import_count=0,
            call_count=0,
            import_locations=[],
            used_symbols=[],
        )
    return module_usage[base_module]


def parse_madge_format(
    data: Dict[str, Any], language: str
) -> tuple[List[ImportEntry], List[CallEdge], Dict[str, ModuleUsage]]:
    """Parse madge JSON output ({file: [dependencies]}); returns no call edges."""
    imports = []
    module_usage: Dict[str, ModuleUsage] = {}

    for file_path, dependencies in data.items():
        if not isinstance(dependencies, list):
            continue

        for dep in dependencies:
            if not isinstance(dep, str):
                continue

            imports.append(
                ImportEntry(
                    module=dep,
                    file=file_path,
                    line=0,  # madge provides no line numbers
                    imported_symbols=[],
                    is_dynamic=False,
                )
            )

            if _is_external_module(dep):
                base_module = normalize_module_name(dep, language)
                usage = _get_or_create_module_usage(module_usage, base_module)
                usage.import_count += 1
                if file_path not in usage.import_locations:
                    usage.import_locations.append(file_path)

    return imports, [], module_usage


def _track_module_call(module_usage: Dict[str, ModuleUsage], target: str, language: str) -> None:
    """Track a call edge's module usage and used symbol."""
    if "." not in target:
        return
    module = target.rsplit(".", 1)[0]
    base_module = normalize_module_name(module, language)
    usage = _get_or_create_module_usage(module_usage, base_module)
    usage.call_count += 1

    symbol = target.rsplit(".", 1)[-1]
    if symbol not in usage.used_symbols:
        usage.used_symbols.append(symbol)


def _track_module_import(
    module_usage: Dict[str, ModuleUsage],
    target: str,
    language: str,
    source_info: Dict[str, Any],
    imports: List[ImportEntry],
    seen_imports: set[tuple[str, str]],
) -> None:
    """Track a uses edge's import and module usage."""
    if "." not in target:
        return

    module = target.rsplit(".", 1)[0]
    symbol = target.rsplit(".", 1)[-1]
    file_path = source_info.get("file", "")
    import_key = (module, file_path)

    if import_key not in seen_imports:
        seen_imports.add(import_key)
        imports.append(
            ImportEntry(
                module=module,
                file=file_path,
                line=source_info.get("line", 0),
                imported_symbols=[symbol],
                is_dynamic=False,
            )
        )

        base_module = normalize_module_name(module, language)
        usage = _get_or_create_module_usage(module_usage, base_module)
        usage.import_count += 1
        if file_path and file_path not in usage.import_locations:
            usage.import_locations.append(file_path)

    base_module = normalize_module_name(module, language)
    if base_module in module_usage and symbol not in module_usage[base_module].used_symbols:
        module_usage[base_module].used_symbols.append(symbol)


def parse_pyan_format(
    data: Dict[str, Any], language: str
) -> tuple[List[ImportEntry], List[CallEdge], Dict[str, ModuleUsage]]:
    """Parse pyan JSON output (nodes + calls/uses edges)."""
    imports: List[ImportEntry] = []
    calls: List[CallEdge] = []
    module_usage: Dict[str, ModuleUsage] = {}

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    node_info: Dict[str, Dict[str, Any]] = {}
    for node in nodes:
        name = node.get("name", "")
        node_info[name] = {
            "file": node.get("file", ""),
            "line": node.get("line", 0),
            "type": node.get("type", ""),
        }

    seen_imports: set[tuple[str, str]] = set()

    for edge in edges:
        source = edge.get("source", "")
        target = edge.get("target", "")
        edge_type = edge.get("type", "calls")
        source_info = node_info.get(source, {})

        if edge_type == "calls":
            calls.append(
                CallEdge(
                    caller=source,
                    callee=target,
                    file=source_info.get("file", ""),
                    line=source_info.get("line", 0),
                    call_type="direct",
                )
            )
            _track_module_call(module_usage, target, language)

        elif edge_type == "uses":
            _track_module_import(module_usage, target, language, source_info, imports, seen_imports)

    return imports, calls, module_usage


def parse_generic_format(
    data: Dict[str, Any], language: str
) -> tuple[List[ImportEntry], List[CallEdge], Dict[str, ModuleUsage]]:
    """Parse the generic callgraph format."""
    imports = []
    calls = []
    module_usage: Dict[str, ModuleUsage] = {}

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
    if "nodes" in data and "edges" in data:
        nodes = data.get("nodes", [])
        if nodes and isinstance(nodes[0], dict):
            if "package" in nodes[0]:
                return "go-callvis"
            return "pyan"

    if "imports" in data or "calls" in data:
        return "generic"

    if all(isinstance(v, list) for v in data.values() if v):
        return "madge"

    return "unknown"
