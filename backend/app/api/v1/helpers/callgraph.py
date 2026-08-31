"""Helper functions for callgraph endpoints."""

from typing import Any

from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.v1.helpers.projects import is_write_superuser
from app.core.constants import (
    PROJECT_ROLE_ADMIN,
    PROJECT_ROLE_EDITOR,
    PROJECT_ROLE_VIEWER,
    PROJECT_ROLES,
    TEAM_ROLE_ADMIN,
)
from app.core.permissions import Permissions, has_permission
from app.models.callgraph import CallEdge, ImportEntry, ModuleUsage
from app.models.user import User
from app.repositories import ProjectRepository, TeamRepository
from app.services.aggregation.components import canonical_module_key, npm_package_key

_MSG_ACCESS_DENIED = "Access denied"
_NODE_MODULES = "node_modules/"
_ANALYZED_MODULES_KEY = "__analyzed_modules__"


def _member_role(members: list[dict[str, Any]], user_id: str) -> str | None:
    """Return the role of ``user_id`` in a members list, or None if absent."""
    for member in members:
        if member.get("user_id") == user_id:
            return member.get("role")
    return None


async def _effective_project_role(
    project: dict[str, Any],
    user_id: str,
    team_repo: TeamRepository,
) -> str | None:
    """Return MAX(direct member role, team-derived role), or None if not a member."""
    roles = []

    direct_role = _member_role(project.get("members", []), user_id)
    if direct_role:
        roles.append(direct_role)

    team_id = project.get("team_id")
    if team_id:
        team = await team_repo.get_raw_by_id(team_id)
        if team:
            team_role = _member_role(team.get("members", []), user_id)
            if team_role:
                roles.append(PROJECT_ROLE_ADMIN if team_role == TEAM_ROLE_ADMIN else PROJECT_ROLE_VIEWER)

    if not roles:
        return None
    return max(roles, key=PROJECT_ROLES.index)


async def check_callgraph_access(
    project_id: str,
    user: User,
    db: AsyncIOMotorDatabase,
    require_write: bool = False,
) -> dict[str, Any]:
    """Verify callgraph access and return the raw project document, or raise 403/404.

    Mirrors ``check_project_access``: project:update/project:delete is the write
    superuser, project:read_all is read-only, members need editor or admin to write.
    """
    project_repo = ProjectRepository(db)
    team_repo = TeamRepository(db)

    project = await project_repo.get_raw_by_id(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if is_write_superuser(user):
        return project

    if not require_write and has_permission(user.permissions, Permissions.PROJECT_READ_ALL):
        return project

    role = await _effective_project_role(project, str(user.id), team_repo)
    if role is None:
        raise HTTPException(status_code=403, detail=_MSG_ACCESS_DENIED)

    if require_write and PROJECT_ROLES.index(role) < PROJECT_ROLES.index(PROJECT_ROLE_EDITOR):
        raise HTTPException(status_code=403, detail=_MSG_ACCESS_DENIED)

    return project


def _canonical_module_list(names: Any, language: str) -> list[str]:
    """Canonicalise and de-duplicate an uploaded analyzed_modules list, order-stable."""
    if not isinstance(names, list):
        return []

    result: list[str] = []
    for name in names:
        if not isinstance(name, str):
            continue
        key = canonical_module_key(name, language)
        if key and key not in result:
            result.append(key)
    return result


def _get_or_create_module_usage(module_usage: dict[str, ModuleUsage], base_module: str) -> ModuleUsage:
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


def _madge_package(dep: str) -> str | None:
    """Package name of a madge dependency, or None when it is a first-party source file."""
    if _NODE_MODULES in dep:
        return npm_package_key(dep.rsplit(_NODE_MODULES, 1)[1])

    if "/" not in dep and "." not in dep:
        return dep

    return None


def _record_madge_dep(
    dep: str,
    file_path: str,
    language: str,
    imports: list[ImportEntry],
    module_usage: dict[str, ModuleUsage],
) -> None:
    """Record one madge dependency; only external packages get a ModuleUsage."""
    imports.append(
        ImportEntry(
            module=dep,
            file=file_path,
            line=0,  # madge provides no line numbers
            imported_symbols=[],
            is_dynamic=False,
        )
    )

    package = _madge_package(dep)
    if package is None:
        return

    usage = _get_or_create_module_usage(module_usage, canonical_module_key(package, language))
    usage.import_count += 1
    if file_path not in usage.import_locations:
        usage.import_locations.append(file_path)


def parse_madge_format(
    data: dict[str, Any], language: str
) -> tuple[list[ImportEntry], list[CallEdge], dict[str, ModuleUsage], list[str]]:
    """Parse madge JSON output ({file: [dependencies]}); returns no call edges."""
    imports: list[ImportEntry] = []
    module_usage: dict[str, ModuleUsage] = {}
    analyzed_modules = _canonical_module_list(data.get(_ANALYZED_MODULES_KEY), language)

    for file_path, dependencies in data.items():
        if file_path == _ANALYZED_MODULES_KEY or not isinstance(dependencies, list):
            continue
        for dep in dependencies:
            if isinstance(dep, str) and dep:
                _record_madge_dep(dep, file_path, language, imports, module_usage)

    return imports, [], module_usage, analyzed_modules


def _record_generic_import(
    imp: dict[str, Any],
    language: str,
    imports: list[ImportEntry],
    module_usage: dict[str, ModuleUsage],
) -> None:
    """Record one generic-format import entry and its module usage."""
    module = imp.get("module", "")
    file_path = imp.get("file", "")
    symbols = imp.get("symbols", [])

    imports.append(
        ImportEntry(
            module=module,
            file=file_path,
            line=imp.get("line", 0),
            imported_symbols=symbols,
            is_dynamic=False,
        )
    )

    if not module or module.startswith(("./", "../")):
        return

    usage = _get_or_create_module_usage(module_usage, canonical_module_key(module, language))
    usage.import_count += 1
    if file_path and file_path not in usage.import_locations:
        usage.import_locations.append(file_path)
    for symbol in symbols:
        if symbol not in usage.used_symbols:
            usage.used_symbols.append(symbol)


def _record_generic_call(
    call: dict[str, Any],
    language: str,
    calls: list[CallEdge],
    module_usage: dict[str, ModuleUsage],
) -> None:
    """Record one generic-format call edge and its module usage."""
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
    if not module:
        return

    usage = _get_or_create_module_usage(module_usage, canonical_module_key(module, language))
    usage.call_count += 1
    func = call.get("callee_function", "")
    if func and func not in usage.used_symbols:
        usage.used_symbols.append(func)


def parse_generic_format(
    data: dict[str, Any], language: str
) -> tuple[list[ImportEntry], list[CallEdge], dict[str, ModuleUsage], list[str]]:
    """Parse the generic callgraph format."""
    imports: list[ImportEntry] = []
    calls: list[CallEdge] = []
    module_usage: dict[str, ModuleUsage] = {}
    analyzed_modules = _canonical_module_list(data.get("analyzed_modules"), language)

    for imp in data.get("imports", []):
        _record_generic_import(imp, language, imports, module_usage)

    for call in data.get("calls", []):
        _record_generic_call(call, language, calls, module_usage)

    return imports, calls, module_usage, analyzed_modules


def detect_format(data: dict[str, Any]) -> str:
    """Auto-detect the callgraph wire format: madge, generic or unknown."""
    if "imports" in data or "calls" in data or "analyzed_modules" in data:
        return "generic"

    file_entries = {key: value for key, value in data.items() if key != _ANALYZED_MODULES_KEY}
    if not file_entries or not all(
        isinstance(deps, list) and all(isinstance(dep, str) for dep in deps) for deps in file_entries.values()
    ):
        return "unknown"

    # An all-empty graph is only meaningful alongside a coverage universe; without one it is
    # indistinguishable from an unrelated payload whose values happen to be empty lists.
    if any(file_entries.values()) or _ANALYZED_MODULES_KEY in data:
        return "madge"

    return "unknown"
