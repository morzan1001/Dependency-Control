"""Holds every tool argument to the type, vocabulary and range its schema declares before a handler reads it."""

from typing import Any

from ._helpers import _clamp_limit
from .definitions import TOOL_DEFINITIONS

_DECLARED_PROPERTIES: dict[str, dict[str, dict[str, Any]]] = {
    definition["function"]["name"]: definition["function"]["parameters"].get("properties", {})
    for definition in TOOL_DEFINITIONS
}


class ToolArgumentError(ValueError):
    """An argument whose type or value differs from what its tool declares."""


def _conforms(schema: dict[str, Any], value: Any) -> bool:
    declared = schema.get("type")
    if declared == "string":
        return isinstance(value, str)
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "integer":
        # _clamp_limit coerces a numeric string, and models send limits as "10".
        return isinstance(value, (int, float, str)) and not isinstance(value, bool)
    return False


def _checked(name: str, schema: dict[str, Any], value: Any) -> Any:
    if schema.get("type") == "array":
        # A lone item stands for the one-element list _ensure_list turns it into.
        if isinstance(value, list):
            return [_checked(name, schema["items"], item) for item in value]
        return _checked(name, schema["items"], value)
    if not _conforms(schema, value):
        raise ToolArgumentError(f"Argument '{name}' must be of type {schema.get('type')}")
    members = schema.get("enum")
    if members:
        spelling = next((member for member in members if member.casefold() == value.casefold()), None)
        if spelling is None:
            raise ToolArgumentError(f"Argument '{name}' must be one of: {', '.join(members)}")
        return spelling
    return value


def checked_arguments(tool_name: str, arguments: Any) -> dict[str, Any]:
    """Declared arguments typed, defaulted and clamped; extra keys are dropped so the model still gets an answer."""
    if not isinstance(arguments, dict):
        raise ToolArgumentError("Tool arguments must be a JSON object")
    declared = _DECLARED_PROPERTIES.get(tool_name, {})
    checked: dict[str, Any] = {
        name: None if value is None else _checked(name, declared[name], value)
        for name, value in arguments.items()
        if name in declared
    }
    for name, schema in declared.items():
        if "maximum" in schema:
            checked[name] = _clamp_limit(checked.get(name), schema["default"], schema["maximum"])
        elif "default" in schema and not checked.get(name):
            checked[name] = schema["default"]
    return checked
