"""Helper functions for callgraph endpoints."""

from collections.abc import Callable
from typing import Any, NamedTuple

from app.models.callgraph import ModuleUsage
from app.services.component_identity import canonical_callgraph_language, canonical_module_key, npm_package_key

_NODE_MODULES = "node_modules/"
_ANALYZED_MODULES_KEY = "__analyzed_modules__"


class ParsedCallgraph(NamedTuple):
    module_usage: dict[str, ModuleUsage]
    analyzed_modules: list[str]
    total_imports: int
    total_calls: int
    source_files: int


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
        module_usage[base_module] = ModuleUsage(module=base_module)
    return module_usage[base_module]


def _madge_package(dep: str) -> str | None:
    """Package name of a madge dependency, or None when it is a first-party source file."""
    if _NODE_MODULES in dep:
        return npm_package_key(dep.rsplit(_NODE_MODULES, 1)[1])

    if "/" not in dep and "." not in dep:
        return dep

    return None


def _record_madge_dep(dep: str, file_path: str, language: str, module_usage: dict[str, ModuleUsage]) -> None:
    """Record one madge dependency; only external packages get a ModuleUsage."""
    package = _madge_package(dep)
    if package is None:
        return

    usage = _get_or_create_module_usage(module_usage, canonical_module_key(package, language))
    usage.import_count += 1
    usage.import_locations.append(file_path)


def parse_madge_format(data: dict[str, Any], language: str) -> ParsedCallgraph:
    """Parse madge JSON output ({file: [dependencies]}); returns no call edges."""
    module_usage: dict[str, ModuleUsage] = {}
    analyzed_modules = _canonical_module_list(data.get(_ANALYZED_MODULES_KEY), language)
    total_imports = source_files = 0

    for file_path, dependencies in data.items():
        if file_path == _ANALYZED_MODULES_KEY or not isinstance(dependencies, list):
            continue
        valid = [dep for dep in dependencies if isinstance(dep, str) and dep]
        for dep in valid:
            _record_madge_dep(dep, file_path, language, module_usage)
        total_imports += len(valid)
        source_files += bool(valid)

    _dedupe_module_usage(module_usage)
    return ParsedCallgraph(module_usage, analyzed_modules, total_imports, 0, source_files)


def _record_generic_import(imp: dict[str, Any], language: str, module_usage: dict[str, ModuleUsage]) -> None:
    """Record one generic-format import entry in its module's usage."""
    module = imp.get("module", "")
    file_path = imp.get("file", "")
    symbols = imp.get("symbols", [])
    well_typed = isinstance(module, str) and isinstance(file_path, str) and isinstance(symbols, list)
    if not well_typed or not all(isinstance(symbol, str) for symbol in symbols):
        raise ValueError("an import needs a string module and file and a list of string symbols")

    if not module or module.startswith(("./", "../")):
        return

    usage = _get_or_create_module_usage(module_usage, canonical_module_key(module, language))
    usage.import_count += 1
    if file_path:
        usage.import_locations.append(file_path)
    usage.used_symbols.extend(symbols)


def _record_generic_call(call: dict[str, Any], language: str, module_usage: dict[str, ModuleUsage]) -> None:
    """Record one generic-format call edge in its callee module's usage."""
    module = call.get("callee_module", "")
    func = call.get("callee_function", "")
    caller_file = call.get("caller_file", "")
    if not (isinstance(module, str) and isinstance(func, str) and isinstance(caller_file, str)):
        raise ValueError("a call needs a string callee_module, callee_function and caller_file")

    if not module:
        return

    usage = _get_or_create_module_usage(module_usage, canonical_module_key(module, language))
    usage.call_count += 1
    if func:
        usage.used_symbols.append(func)
    # A file that calls into a package references it, even when the producer emitted no import for it.
    if caller_file:
        usage.import_locations.append(caller_file)


def parse_generic_format(data: dict[str, Any], language: str) -> ParsedCallgraph:
    """Parse the generic callgraph format."""
    imports = data.get("imports", [])
    calls = data.get("calls", [])
    module_usage: dict[str, ModuleUsage] = {}

    for imp in imports:
        _record_generic_import(imp, language, module_usage)

    for call in calls:
        _record_generic_call(call, language, module_usage)

    _dedupe_module_usage(module_usage)
    return ParsedCallgraph(
        module_usage,
        _canonical_module_list(data.get("analyzed_modules"), language),
        total_imports=len(imports),
        total_calls=len(calls),
        source_files=len({imp.get("file", "") for imp in imports}),
    )


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


Parser = Callable[[dict[str, Any], str], ParsedCallgraph]

_FORMAT_PARSERS: dict[str, Parser] = {"madge": parse_madge_format, "generic": parse_generic_format}
# The one format that names its own language: madge only ever runs over a JS/TS tree.
_FORMAT_LANGUAGES = {"madge": "javascript"}


def resolve_callgraph_payload(
    request_format: str, language: str | None, data: dict[str, Any]
) -> tuple[str, str, Parser]:
    """(format, canonical language, parser) of a posted callgraph; ValueError for what it lacks or nothing supports."""
    format_type = detect_format(data) if request_format == "auto" else request_format
    if format_type == "unknown":
        raise ValueError("Could not auto-detect callgraph format. Please specify 'format' explicitly.")
    language = language or _FORMAT_LANGUAGES.get(format_type)
    if not language:
        raise ValueError(f"'language' is required for '{format_type}' callgraph payloads")
    canonical = canonical_callgraph_language(language)
    parser = _FORMAT_PARSERS.get(format_type)
    if parser is None:
        raise ValueError(f"Unsupported format: {format_type}")
    return format_type, canonical, parser
