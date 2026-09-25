"""Holds every tool argument to the JSON type its schema declares before a handler builds a query from it."""

from typing import Any

from .definitions import TOOL_DEFINITIONS

_DECLARED_PROPERTIES: dict[str, dict[str, dict[str, Any]]] = {
    definition["function"]["name"]: definition["function"]["parameters"].get("properties", {})
    for definition in TOOL_DEFINITIONS
}


class ToolArgumentError(ValueError):
    """An argument whose JSON type differs from the one its tool declares."""


def _conforms(schema: dict[str, Any], value: Any) -> bool:
    declared = schema.get("type")
    if declared == "string":
        return isinstance(value, str)
    if declared == "integer":
        # _clamp_limit coerces a numeric string, and models send limits as "10".
        return isinstance(value, (int, float, str)) and not isinstance(value, bool)
    if declared == "array":
        # A lone item stands for the one-element list _ensure_list turns it into.
        items = value if isinstance(value, list) else [value]
        return all(_conforms(schema["items"], item) for item in items)
    return False


def checked_arguments(tool_name: str, arguments: Any) -> dict[str, Any]:
    """The arguments the tool declares, each of its declared type; undeclared keys are dropped so a
    model that adds one still gets its answer. A null stays null, which handlers read as not given."""
    if not isinstance(arguments, dict):
        raise ToolArgumentError("Tool arguments must be a JSON object")
    declared = _DECLARED_PROPERTIES.get(tool_name, {})
    checked: dict[str, Any] = {}
    for name, value in arguments.items():
        schema = declared.get(name)
        if schema is None:
            continue
        if value is not None and not _conforms(schema, value):
            raise ToolArgumentError(f"Argument '{name}' must be of type {schema.get('type')}")
        checked[name] = value
    return checked
