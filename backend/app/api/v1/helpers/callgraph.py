from collections.abc import Callable
from typing import Any, NamedTuple

from app.models.callgraph import ModuleUsage
from app.services.component_identity import canonical_callgraph_language, canonical_module_key, npm_package_key

_NODE_MODULES = "node_modules/"
_TYPES_SCOPE = "@types/"
_ANALYZED_MODULES_KEY = "__analyzed_modules__"
_GENERIC_KEYS = ("imports", "calls", "analyzed_modules")


class ParsedCallgraph(NamedTuple):
    module_usage: dict[str, ModuleUsage]
    analyzed_modules: list[str]
    total_imports: int
    total_calls: int
    source_files: int


def _package_key(module: str, language: str) -> str | None:
    """None for '' and a relative specifier ('./x', '../x', Python '.x'), which name first-party code."""
    return canonical_module_key(module, language) if module and not module.startswith(".") else None


def _canonical_module_list(names: Any, language: str) -> list[str]:
    if not isinstance(names, list):
        return []

    return list(dict.fromkeys(key for name in names if isinstance(name, str) and (key := _package_key(name, language))))


def _dedupe_module_usage(module_usage: dict[str, ModuleUsage]) -> None:
    for usage in module_usage.values():
        usage.import_locations = list(dict.fromkeys(usage.import_locations))
        usage.used_symbols = list(dict.fromkeys(usage.used_symbols))


def _get_or_create_module_usage(module_usage: dict[str, ModuleUsage], base_module: str) -> ModuleUsage:
    if base_module not in module_usage:
        module_usage[base_module] = ModuleUsage(module=base_module)
    return module_usage[base_module]


def _madge_package(dep: str) -> str | None:
    if _NODE_MODULES in dep:
        package = npm_package_key(dep.rsplit(_NODE_MODULES, 1)[1])
        # TypeScript resolves an import of an untyped package to its stub, @types/<name> or @types/<scope>__<name>.
        if package.startswith(_TYPES_SCOPE):
            name = package.removeprefix(_TYPES_SCOPE)
            return "@" + name.replace("__", "/", 1) if "__" in name else name
        return package

    if "/" not in dep and "." not in dep:
        return dep

    return None


def _record_madge_dep(dep: str, file_path: str, language: str, module_usage: dict[str, ModuleUsage]) -> None:
    package = _madge_package(dep)
    if package is None:
        return

    usage = _get_or_create_module_usage(module_usage, canonical_module_key(package, language))
    usage.import_count += 1
    usage.import_locations.append(file_path)


def parse_madge_format(data: dict[str, Any], language: str) -> ParsedCallgraph:
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
    module = imp.get("module", "")
    file_path = imp.get("file", "")
    symbols = imp.get("symbols", [])
    well_typed = isinstance(module, str) and isinstance(file_path, str) and isinstance(symbols, list)
    if not well_typed or not all(isinstance(symbol, str) for symbol in symbols):
        raise ValueError("an import needs a string module and file and a list of string symbols")

    key = _package_key(module, language)
    if key is None:
        return

    usage = _get_or_create_module_usage(module_usage, key)
    usage.import_count += 1
    if file_path:
        usage.import_locations.append(file_path)
    usage.used_symbols.extend(symbols)


def _record_generic_call(call: dict[str, Any], language: str, module_usage: dict[str, ModuleUsage]) -> None:
    module = call.get("callee_module", "")
    func = call.get("callee_function", "")
    caller_file = call.get("caller_file", "")
    if not (isinstance(module, str) and isinstance(func, str) and isinstance(caller_file, str)):
        raise ValueError("a call needs a string callee_module, callee_function and caller_file")

    key = _package_key(module, language)
    if key is None:
        return

    usage = _get_or_create_module_usage(module_usage, key)
    usage.call_count += 1
    if func:
        usage.used_symbols.append(func)
    # A file that calls into a package references it, even when the producer emitted no import for it.
    if caller_file:
        usage.import_locations.append(caller_file)


def parse_generic_format(data: dict[str, Any], language: str) -> ParsedCallgraph:
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
    if any(key in data for key in _GENERIC_KEYS):
        return "generic"

    file_entries = {key: value for key, value in data.items() if key != _ANALYZED_MODULES_KEY}
    if not file_entries or not all(
        isinstance(deps, list) and all(isinstance(dep, str) for dep in deps) for deps in file_entries.values()
    ):
        return "unknown"

    # Without a coverage universe an all-empty graph is indistinguishable from an unrelated payload of empty lists.
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
    format_type = detect_format(data) if request_format == "auto" else request_format
    if format_type == "unknown":
        raise ValueError("Could not auto-detect callgraph format. Please specify 'format' explicitly.")
    # The upload schema pins the format, but an ad-hoc posted callgraph carries any string.
    if format_type not in _FORMAT_PARSERS:
        raise ValueError(f"Unsupported format: {format_type}")
    if format_type == "generic" and not any(key in data for key in _GENERIC_KEYS):
        raise ValueError(f"A generic callgraph needs at least one of {', '.join(_GENERIC_KEYS)}")
    language = language or _FORMAT_LANGUAGES.get(format_type)
    if not language:
        raise ValueError(f"'language' is required for '{format_type}' callgraph payloads")
    return format_type, canonical_callgraph_language(language), _FORMAT_PARSERS[format_type]
