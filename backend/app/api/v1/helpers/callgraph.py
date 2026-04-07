"""
Callgraph Helper Functions

Helper functions for callgraph endpoints, extracted for better
code organization and reusability.
"""

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
    """
    Verify user has access to the project's callgraph.

    Args:
        project_id: The project ID
        user: The current user
        db: Database connection
        require_write: If True, require write permission (for upload/delete)

    Returns:
        The project document if access is granted

    Raises:
        HTTPException: 404 if project not found, 403 if access denied
    """
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    project = await project_repo.get_raw_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    user_id = str(user.id)

    # Check global permissions
    if _has_global_permission(user, require_write):
        return project

    # Check team membership
    team_id = project.get("team_id")
    if team_id:
        team = await team_repo.get_raw_by_id(team_id)
        if team and _is_member(team.get("members", []), user_id):
            return project

    # Check direct project membership
    if _is_member(project.get("members", []), user_id):
        return project

    raise HTTPException(status_code=403, detail="Access denied")


def normalize_module_name(module: str, _language: str) -> str:
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
            if _is_external_module(dep):
                base_module = normalize_module_name(dep, language)
                usage = _get_or_create_module_usage(module_usage, base_module)
                usage.import_count += 1
                if file_path not in usage.import_locations:
                    usage.import_locations.append(file_path)

    # Madge doesn't provide call edges, only imports
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

    # Create import entry if not already seen
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

        # Update module usage
        base_module = normalize_module_name(module, language)
        usage = _get_or_create_module_usage(module_usage, base_module)
        usage.import_count += 1
        if file_path and file_path not in usage.import_locations:
            usage.import_locations.append(file_path)

    # Always track the symbol
    base_module = normalize_module_name(module, language)
    if base_module in module_usage and symbol not in module_usage[base_module].used_symbols:
        module_usage[base_module].used_symbols.append(symbol)


def parse_pyan_format(
    data: Dict[str, Any], language: str
) -> tuple[List[ImportEntry], List[CallEdge], Dict[str, ModuleUsage]]:
    """
    Parse pyan JSON output format.

    Pyan format:
    {
        "nodes": [{"name": "module.func", "type": "function", "file": "...", "line": 10}],
        "edges": [{"source": "module.func", "target": "other.func", "type": "calls|uses"}]
    }
    """
    imports: List[ImportEntry] = []
    calls: List[CallEdge] = []
    module_usage: Dict[str, ModuleUsage] = {}

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    # Build node lookup
    node_info: Dict[str, Dict[str, Any]] = {}
    for node in nodes:
        name = node.get("name", "")
        node_info[name] = {
            "file": node.get("file", ""),
            "line": node.get("line", 0),
            "type": node.get("type", ""),
        }

    # Track seen imports to avoid duplicates
    seen_imports: set[tuple[str, str]] = set()

    # Process edges
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
