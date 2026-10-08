import ast
import sys
import tomllib
from importlib.metadata import packages_distributions, requires
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

_BACKEND = Path(__file__).resolve().parents[2]


def _unconditionally_installed() -> set[str]:
    """Declared distributions plus what they require outside any extra: an extra can be dropped without notice."""
    pyproject = tomllib.loads((_BACKEND / "pyproject.toml").read_text())
    pending = [canonicalize_name(name) for name in pyproject["tool"]["poetry"]["dependencies"] if name != "python"]
    closure: set[str] = set()
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        closure.add(name)
        for spec in requires(name) or []:
            requirement = Requirement(spec)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                pending.append(canonicalize_name(requirement.name))
    return closure


def _top_level_imports() -> set[str]:
    modules: set[str] = set()
    for path in (_BACKEND / "app").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                modules.update(alias.name.partition(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules.add(node.module.partition(".")[0])
    return {module for module in modules if module != "app" and module not in sys.stdlib_module_names}


def test_every_imported_package_is_installed_without_relying_on_an_extra():
    installed = _unconditionally_installed()
    distributions = packages_distributions()

    undeclared = {
        module: distributions.get(module)
        for module in _top_level_imports()
        if not any(canonicalize_name(dist) in installed for dist in distributions.get(module, []))
    }

    assert undeclared == {}
