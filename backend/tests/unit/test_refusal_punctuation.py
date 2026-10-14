import ast
import re
from collections import ChainMap
from collections.abc import Iterator, Mapping
from pathlib import Path

_APP = Path(__file__).resolve().parents[2] / "app"
# A sentence ends at '.', '!' or '?' followed by a space and a capital or an interpolated value.
_SENTENCE_BREAK = re.compile(r"[.!?] +[A-Z{]")


def _module_constants(tree: ast.Module) -> dict[str, ast.expr]:
    constants: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            constants.update({target.id: node.value for target in node.targets if isinstance(target, ast.Name)})
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            constants[node.target.id] = node.value
    return constants


def _text(node: ast.expr | None, constants: Mapping[str, ast.expr]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(part.value if isinstance(part, ast.Constant) else "{}" for part in node.values)
    if isinstance(node, ast.Name) and node.id in constants:
        return _text(constants[node.id], constants)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _text(node.func.value, constants)
    return None


def _refusals() -> Iterator[tuple[str, str]]:
    trees = {path: ast.parse(path.read_text()) for path in sorted(_APP.rglob("*.py"))}
    local = {path: _module_constants(tree) for path, tree in trees.items()}
    everywhere = ChainMap(*local.values())
    for path, tree in trees.items():
        constants = ChainMap(local[path], everywhere)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "HTTPException":
                detail = next((kw.value for kw in node.keywords if kw.arg == "detail"), None)
                text = _text(detail, constants)
                if text is not None:
                    yield f"{path.relative_to(_APP)}:{node.lineno}", text


def test_a_one_sentence_refusal_ends_without_a_period_like_the_others():
    offenders = [
        f"{where}: {text}"
        for where, text in _refusals()
        if text.endswith(".") and not _SENTENCE_BREAK.search(text[:-1])
    ]

    assert offenders == []


def test_the_scan_reads_literal_constant_and_interpolated_refusals():
    texts = {text for _, text in _refusals()}

    assert {"Analysis job not found", "Conversation not found", "Unknown analyzers: {}"} <= texts
