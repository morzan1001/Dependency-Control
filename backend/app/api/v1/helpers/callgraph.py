"""Helper functions for callgraph endpoints."""

from typing import Any


from app.models.callgraph import CallEdge, ImportEntry, ModuleUsage
from app.services.aggregation.components import canonical_module_key, npm_package_key

_NODE_MODULES = "node_modules/"
_ANALYZED_MODULES_KEY = "__analyzed_modules__"


def callgraph_entry_count(data: dict[str, Any]) -> int:
    """What either parser walks, counted off the raw payload: every top-level list, plus the
    symbols each import names."""
    total = 0
    for value in data.values():
        if not isinstance(value, list):
            continue
        total += len(value)
        total += sum(
            len(entry["symbols"])
            for entry in value
            if isinstance(entry, dict) and isinstance(entry.get("symbols"), list)
        )
    return total


def _canonical_module_list(names: Any, language: str) -> list[str]:
    """Canonicalise and de-duplicate an uploaded analyzed_modules list, order-stable."""
    if not isinstance(names, list):
        return []

    return list(
        dict.fromkeys(key for name in names if isinstance(name, str) and (key := canonical_module_key(name, language)))
    )


def _dedupe_module_usage(module_usage: dict[str, ModuleUsage]) -> None:
    """Collapse the lists the record helpers append to, keeping first-seen order."""
    for usage in module_usage.values():
        usage.import_locations = list(dict.fromkeys(usage.import_locations))
        usage.used_symbols = list(dict.fromkeys(usage.used_symbols))


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

    _dedupe_module_usage(module_usage)
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
    if file_path:
        usage.import_locations.append(file_path)
    usage.used_symbols.extend(symbols)


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
    if func:
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

    _dedupe_module_usage(module_usage)
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
