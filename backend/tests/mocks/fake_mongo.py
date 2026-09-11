"""In-process fake MongoDB for tests.

Consolidates what used to be two parallel implementations (`tests/unit/conftest.py`
and `tests/integration/conftest.py`) into a single source of truth. Supports the
operators that the application code actually uses — extend here, not in conftest.

Supported query operators
-------------------------
- Equality and dotted paths (``members.user_id`` recurses into list elements)
- ``$eq``, ``$in``, ``$nin``, ``$ne``, ``$exists``, ``$size``, ``$all``
- ``$regex`` (with ``$options: "i"`` for case-insensitive)
- Range: ``$gt``, ``$gte``, ``$lt``, ``$lte``
- ``$elemMatch``: an operator-only condition applies to the element itself, so a scalar
  array matches; anything else is a query document only a sub-document can satisfy.
- Logical: top-level ``$or``, ``$and``, ``$nor``
- Anything else raises ``OperationFailure``, as the server does; matching on an
  operator the fake cannot evaluate would report a wider scope than the query asks for.

Supported update operators
--------------------------
- ``$set`` (including ``a.$[ident].b`` paths with ``array_filters``), ``$setOnInsert``,
  ``$unset``, ``$inc``, ``$addToSet``, ``$push``, ``$pull``
- The aggregation-pipeline form, ``update_one(filter, [{"$set": ...}, ...])``, with the
  ``$set``/``$addFields``, ``$unset``, ``$project`` and ``$replaceRoot`` stages.
- Two modifiers may not touch overlapping paths: the parse raises ``OperationFailure``
  with code 40 before the filter runs, so ``$pull`` and ``$addToSet`` on one array is
  refused here exactly as production refuses it.
- Anything else raises ``OperationFailure``; silently ignoring a modifier turns a write
  into a no-op the test then reports as success.

``tests/mocks/mongo_array_cases.py`` holds the array-operator expectations measured against
Percona Server for MongoDB 8.0.17-6, and drives both this fake and a real server.

Server-side behaviour that tests rely on
----------------------------------------
- Projections in ``find``/``find_one``, inclusion and exclusion, dotted paths
  included, so a too-narrow projection surfaces here instead of in production.
- BSON datetimes: a written aware datetime is stored (and read back) as naive
  UTC truncated to the millisecond, and a query value is normalised the same way
  before comparison, matching what the driver puts on the wire.
- BSON compares by type before value, so a bool never equals the number Python
  would call it equal to: ``{"$ne": True}`` keeps a document holding ``1``.
- Cross-type BSON ordering: sorts, ``$min`` and ``$max`` rank a mixed column
  (missing < number < string < date) instead of raising, while a range query
  brackets to its bound's type and skips the other types outright.
- ``$group`` drops a grouping key the document does not carry rather than
  binding it to null, and its ``$push``/``$addToSet`` collect nothing for a document
  that lacks the field while still collecting an explicit null.
- An array field answers ``$eq``/``$in``/``$nin``/``$ne`` and a bare equality both as a
  whole and element by element, so ``$ne: []`` excludes the empty array and a literal
  ``["A", "B"]`` finds the document holding exactly that.
- Only false, null and zero are false to ``$cond``/``$switch``; ``""`` and
  ``[]`` are true.
- A cursor is consumed as it is read: ``to_list(length=n)`` hands back the next
  n documents and finally an empty list, and iterating a drained cursor yields
  nothing, so a paging loop terminates here as it does there.
- ``insert_one``/``insert_many`` stamp a generated ``ObjectId`` onto the caller's
  document, so code that reads the new id back without a round trip works, and a
  later insert never reuses the key of a deleted one.
- ``bulk_write`` reports matched, modified and upserted counts, and does not count
  an update that changed nothing.

Known divergences, none of which the application issues
-------------------------------------------------------
- ``distinct`` resolves only top-level scalar fields: it does not follow a dotted
  path and does not flatten an array-valued one.
- ``$push`` takes a plain value; the ``$each``/``$slice``/``$sort`` modifiers are
  appended verbatim instead of being applied. ``$addToSet`` does unwrap ``$each``.
- ``count_documents`` ignores ``skip``.
- A ``$group`` ``$addToSet`` reports its members in first-seen order. The server's
  order is unspecified, so agreement on it is not something a test can pin.

Supported aggregation stages
----------------------------
- ``$match``, ``$sort`` (direction must be 1 or -1), ``$group``, ``$project``, ``$limit``
- ``$unwind``, both the string and the
  ``{path, preserveNullAndEmptyArrays, includeArrayIndex}`` forms
- ``$group`` accumulators: ``$sum``, ``$avg``, ``$first``, ``$firstN``, ``$min``,
  ``$max``, ``$addToSet``, ``$push``
- ``$dateTrunc`` truncates to the start of the unit (day/week/month/year; week
  starts Sunday, matching MongoDB's default), in both expressions and
  ``$group._id``, so trend bucketing is exercised end-to-end.

Supported aggregation expression operators (in ``$project`` / accumulator args)
------------------------------------------------------------------------------
- ``$ifNull``, ``$cond``, ``$switch``, ``$toDouble``, ``$toLower``, ``$toString``
- Arrays and maps: ``$size``, ``$setUnion``, ``$setDifference``, ``$objectToArray``,
  ``$arrayToObject``, ``$arrayElemAt``, ``$split``
- Comparison: ``$eq``, ``$ne``, ``$gt``, ``$gte``, ``$lt``, ``$lte``
- Logical: ``$and``, ``$or``
- ``$map``, ``$filter``, ``$let``, ``$mergeObjects``, ``$literal``. A bound ``$$var`` is
  substituted; every other reference still resolves against the root document, as it does
  on the server, so the team-enrichment ``$lookup`` runs here byte-for-byte as it does there.
- ``$$REMOVE`` (field is omitted; mirrors Mongo's $push semantics)
"""

from __future__ import annotations

import asyncio
import copy as _copy
import operator as _op
import re as _re
from datetime import datetime as _datetime
from datetime import timedelta as _timedelta
from datetime import timezone as _timezone
from typing import Any
from unittest.mock import MagicMock

from bson import ObjectId
from pymongo.errors import OperationFailure

from app.core.init_db import RELEASES_UPSERT_KEY_FIELDS


def _truncate_date(value: Any, unit: str) -> Any:
    """Best-effort $dateTrunc: round a datetime down to the start of the unit
    (day/week/month/year). Week starts on Sunday, matching MongoDB's default.
    Non-datetime values pass through unchanged."""
    if not isinstance(value, _datetime):
        return value
    midnight = value.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit == "year":
        return midnight.replace(month=1, day=1)
    if unit == "month":
        return midnight.replace(day=1)
    if unit == "week":
        return midnight - _timedelta(days=(value.weekday() + 1) % 7)
    return midnight  # day (default)


_SET_ON_INSERT = "$setOnInsert"
_CMP = {"$lt": _op.lt, "$lte": _op.le, "$gt": _op.gt, "$gte": _op.ge}
_MICROSECONDS_PER_MILLISECOND = 1000


# ---------------------------------------------------------------------------
# BSON value semantics
# ---------------------------------------------------------------------------


def _naive_utc(value: Any) -> Any:
    """BSON has no offsets and dates are int64 milliseconds: an aware datetime is stored (and read
    back) as naive UTC, and every datetime loses the sub-millisecond digits the wire cannot carry."""
    if not isinstance(value, _datetime):
        return value
    if value.tzinfo is not None:
        value = value.astimezone(_timezone.utc).replace(tzinfo=None)
    return value.replace(microsecond=value.microsecond // _MICROSECONDS_PER_MILLISECOND * _MICROSECONDS_PER_MILLISECOND)


def _bson_equal(left: Any, right: Any) -> bool:
    """Equality with BSON's type ranking: bool is its own type, so ``1`` never equals ``True``."""
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return bool(_naive_utc(left) == _naive_utc(right))


def _bson_identical(left: Any, right: Any) -> bool:
    """Deep equality under BSON's type ranking, so a $set turning ``1`` into ``True`` is a change."""
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_bson_identical(left[key], right[key]) for key in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_bson_identical(a, b) for a, b in zip(left, right))
    return _bson_equal(left, right)


def _bson_same_value(left: Any, right: Any) -> bool:
    """Value equality the way $addToSet dedupes: BSON compares documents byte for byte, so the
    same pairs in a different key order are two distinct values and both survive."""
    if isinstance(left, dict) or isinstance(right, dict):
        if not (isinstance(left, dict) and isinstance(right, dict)):
            return False
        return list(left.keys()) == list(right.keys()) and all(_bson_same_value(left[key], right[key]) for key in left)
    if isinstance(left, list) or isinstance(right, list):
        if not (isinstance(left, list) and isinstance(right, list)):
            return False
        return len(left) == len(right) and all(_bson_same_value(a, b) for a, b in zip(left, right))
    return _bson_equal(left, right)


def _bsonify(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _bsonify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_bsonify(v) for v in value]
    return _naive_utc(value)


def _bson_type_rank(value: Any) -> int:
    """Position of a value's BSON type in the server's cross-type ordering.

    A missing field reaches this as None and shares the null rank, so it sorts
    first ascending. Ints and floats share one rank; bool is its own type and
    therefore never compares against a number.
    """
    if value is None:
        return 1
    if isinstance(value, bool):
        return 6
    if isinstance(value, (int, float)):
        return 2
    if isinstance(value, str):
        return 3
    if isinstance(value, dict):
        return 4
    if isinstance(value, (list, tuple)):
        return 5
    if isinstance(value, _datetime):
        return 7
    return 8


def _bson_type_name(value: Any) -> str:
    """The type name the server puts in a wrong-type write error."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "double"
    if isinstance(value, str):
        return "string"
    if isinstance(value, _datetime):
        return "date"
    if isinstance(value, list):
        return "array"
    return "object"


def _bson_sort_key(value: Any) -> tuple[int, Any]:
    """Mongo orders across BSON types instead of refusing to compare them.

    Verified against the server: ascending puts a missing field before a string
    before a date, so a scan whose date an archive restore left as text sorts
    rather than raising.
    """
    rank = _bson_type_rank(value)
    if rank == 1:
        return (rank, 0)
    if rank == 2:
        return (rank, float(value))
    if rank == 6:
        return (rank, int(value))
    if rank == 7:
        # Equal ranks are all a tuple comparison ever reaches, so the datetimes
        # only ever meet each other, and normalising to naive keeps that legal.
        return (rank, _naive_utc(value))
    if rank == 3:
        return (rank, value)
    # Documents and arrays have no total order in Python; their text form has one.
    return (rank, str(value))


_SORT_DIRECTIONS = frozenset({1, -1})


def _sort_docs(docs: list, sort_spec) -> list:
    """Sort in place by a ``[(field, direction)]`` spec, using BSON ordering.

    A direction outside 1/-1 raises, as the server does; treating 2 as ascending would let a typo
    in a sort spec pass here and fail the query in production.
    """
    for key, direction in reversed(list(sort_spec)):
        if direction not in _SORT_DIRECTIONS:
            raise OperationFailure(f"$sort key ordering must be 1 (for ascending) or -1 (for descending), got {key}")
        docs.sort(key=lambda d, k=key: _bson_sort_key(_resolve_dotted(d, k)), reverse=direction < 0)
    return docs


# ---------------------------------------------------------------------------
# Query matching helpers
# ---------------------------------------------------------------------------


def _has_field(doc: dict, path: str) -> bool:
    """Whether the document carries the path at all, as opposed to holding None there."""
    head, _, rest = path.partition(".")
    if not isinstance(doc, dict) or head not in doc:
        return False
    return _has_field(doc[head], rest) if rest else True


def _resolve_dotted(doc: dict, path: str):
    """Resolve a dotted path against a doc; recurses into list elements."""
    if "." not in path:
        return doc.get(path)
    head, _, rest = path.partition(".")
    cur = doc.get(head)
    if cur is None:
        return None
    if isinstance(cur, list):
        out: list = []
        for el in cur:
            if isinstance(el, dict):
                resolved = _resolve_dotted(el, rest)
                if isinstance(resolved, list):
                    out.extend(resolved)
                elif resolved is not None:
                    out.append(resolved)
        return out if out else None
    if isinstance(cur, dict):
        return _resolve_dotted(cur, rest)
    return None


def _descend_for_update(node: Any, part: str) -> Any:
    """The container one update-path segment deeper, created as a dict when it is missing.
    An index past the end of a list pads with nulls, as the server does."""
    if isinstance(node, list):
        index = int(part)
        node.extend([None] * (index + 1 - len(node)))
        if not isinstance(node[index], (dict, list)):
            node[index] = {}
        return node[index]
    child = node.get(part)
    if not isinstance(child, (dict, list)):
        child = {}
        node[part] = child
    return child


def _match_range_ops(value, ops_dict: dict) -> bool:
    """Evaluate $gt/$gte/$lt/$lte; None values never satisfy a range op."""
    for op_key, cmp_fn in _CMP.items():
        if op_key in ops_dict:
            if value is None:
                return False
            # The driver encodes an aware query value to UTC, so it compares
            # against the stored naive datetime instead of raising.
            left, right = _naive_utc(value), _naive_utc(ops_dict[op_key])
            # A range query is bracketed to the bound's BSON type, so a date
            # bound skips a document holding a string there rather than
            # widening the match.
            if _bson_type_rank(left) != _bson_type_rank(right):
                return False
            if not cmp_fn(_bson_sort_key(left), _bson_sort_key(right)):
                return False
    return True


def _array_filter_identifier(condition: dict) -> str | None:
    """Identifier an array filter binds, e.g. ``{"vuln.id": x}`` -> ``vuln``."""
    for key, value in condition.items():
        if key.startswith("$") and isinstance(value, list):
            for sub in value:
                if isinstance(sub, dict) and (found := _array_filter_identifier(sub)):
                    return found
        elif "." in key:
            return key.split(".", 1)[0]
    return None


def _strip_identifier(condition: dict, identifier: str) -> dict:
    prefix = f"{identifier}."
    stripped: dict = {}
    for key, value in condition.items():
        if key.startswith("$") and isinstance(value, list):
            stripped[key] = [_strip_identifier(sub, identifier) for sub in value]
        elif key.startswith(prefix):
            stripped[key[len(prefix) :]] = value
        else:
            stripped[key] = value
    return stripped


def _array_filter_predicates(array_filters: list | None) -> dict:
    """{identifier: predicate} for ``$[identifier]`` update paths."""
    predicates: dict = {}
    for condition in array_filters or []:
        identifier = _array_filter_identifier(condition)
        if identifier:
            predicates[identifier] = _strip_identifier(condition, identifier)
    return predicates


def _in_allowed(value: Any, allowed: list) -> bool:
    """Mongo's $in accepts regex patterns alongside literals."""
    for candidate in allowed:
        if isinstance(candidate, _re.Pattern):
            if isinstance(value, str) and candidate.search(value):
                return True
        elif _bson_equal(value, candidate):
            return True
    return False


_PULL_ELEMENT = "__element__"
_MATCH_TOP_LEVEL_OPERATORS = frozenset({"$or", "$and", "$nor", "$expr"})
_MATCH_FIELD_OPERATORS = frozenset(
    {"$exists", "$eq", "$in", "$nin", "$ne", "$regex", "$options", "$elemMatch", "$size", "$all", *_CMP}
)


def _matches_value(value: Any, wanted: Any) -> bool:
    """An array field answers an equality both as a whole and element by element, so
    ``{"team_ids": ["A", "B"]}`` and ``{"team_ids": "A"}`` can select the same document."""
    if _bson_equal(value, wanted):
        return True
    return isinstance(value, list) and any(_bson_equal(element, wanted) for element in value)


def _in_matches(value: Any, allowed: list) -> bool:
    """$in/$nin apply the same whole-array-or-element rule as a bare equality."""
    if _in_allowed(value, allowed):
        return True
    return isinstance(value, list) and any(_in_allowed(element, allowed) for element in value)


def _is_operator_condition(condition: dict) -> bool:
    """Whether a condition document is a set of field-level operators applied to the value itself,
    as opposed to a query document that only a sub-document can satisfy.

    Mongo dispatches on the top-level keys alone and refuses a mix of the two, so
    ``{"$gt": 4, "u": 1}`` is an error rather than a conjunction.
    """
    operators = [key for key in condition if key.startswith("$")]
    if not operators:
        return False
    if len(operators) != len(condition):
        plain = next(key for key in condition if not key.startswith("$"))
        raise OperationFailure(f"unknown operator: {plain}", 2)
    # A logical operator combines whole query documents, so it stays on the document branch.
    return not any(op in _MATCH_TOP_LEVEL_OPERATORS for op in operators)


def _elem_matches(element: Any, condition: Any) -> bool:
    """One array element against an $elemMatch / $pull condition."""
    if not isinstance(condition, dict):
        return _bson_equal(element, condition)
    if _is_operator_condition(condition):
        return _match_doc({_PULL_ELEMENT: element}, {_PULL_ELEMENT: condition})
    return isinstance(element, dict) and _match_doc(element, condition)


def _assert_known_operators(query: dict) -> None:
    """Refuse an operator the fake does not implement.

    Ignoring it would match every document, so a broken filter would return more rows than the
    server does and the test would report a wider scope than the code actually selects.
    """
    for key, condition in query.items():
        if key.startswith("$"):
            if key not in _MATCH_TOP_LEVEL_OPERATORS:
                raise OperationFailure(f"unknown top level operator: {key}")
            for sub in condition if isinstance(condition, list) else []:
                if isinstance(sub, dict):
                    _assert_known_operators(sub)
        elif isinstance(condition, dict):
            for unknown in (k for k in condition if k.startswith("$") and k not in _MATCH_FIELD_OPERATORS):
                raise OperationFailure(f"unknown operator: {unknown}")


def _pull_matches(item: Any, condition: Any) -> bool:
    """$pull's condition is a set of operators on the element, a query document, or a literal."""
    return _elem_matches(item, condition)


def _match_doc(doc: dict, query: dict) -> bool:
    """Return True if doc matches a MongoDB query."""
    _assert_known_operators(query)
    for key, condition in query.items():
        if key == "$or":
            if not any(_match_doc(doc, sub) for sub in condition):
                return False
            continue
        if key == "$and":
            if not all(_match_doc(doc, sub) for sub in condition):
                return False
            continue
        if key == "$nor":
            if any(_match_doc(doc, sub) for sub in condition):
                return False
            continue
        if key == "$expr":
            # Unsupported before: an unrecognised operator fell through as "matches".
            if not _eval_bool(doc, condition):
                return False
            continue

        value = _resolve_dotted(doc, key)
        # Mongo dispatches on the top-level keys: a document without any is a literal to equal,
        # so ``{"a": {"b": {"$gt": 0}}}`` asks for that exact sub-document, not a range.
        if not (isinstance(condition, dict) and any(k.startswith("$") for k in condition)):
            if not _matches_value(value, condition):
                return False
            continue
        if "$elemMatch" in condition:
            # A single element has to satisfy every clause; a non-array field never does.
            elements = value if isinstance(value, list) else []
            if not any(_elem_matches(element, condition["$elemMatch"]) for element in elements):
                return False
        if "$size" in condition:
            wanted = condition["$size"]
            if isinstance(wanted, bool) or not isinstance(wanted, (int, float)):
                raise OperationFailure(f"Failed to parse $size. Expected a number in: $size: {wanted!r}", 2)
            if wanted < 0:
                raise OperationFailure(f"Failed to parse $size. Expected a non-negative number in: $size: {wanted}", 2)
            if not isinstance(value, list) or len(value) != wanted:
                return False
        if "$all" in condition:
            wanted = condition["$all"]
            if not isinstance(wanted, list):
                raise OperationFailure("$all needs an array", 2)
            # An empty $all matches nothing at all, rather than every document.
            if not wanted or not all(_matches_value(value, item) for item in wanted):
                return False
        if "$exists" in condition:
            field_present = _resolve_dotted(doc, key) is not None or key in doc
            if bool(condition["$exists"]) != field_present:
                return False
        # $eq/$in/$nin/$ne compare an array field as a whole and element by element, so
        # ``$ne: []`` excludes the empty array and ``$in: [["A"]]`` finds the literal.
        if "$eq" in condition and not _matches_value(value, condition["$eq"]):
            return False
        if "$in" in condition and not _in_matches(value, condition["$in"]):
            return False
        if "$nin" in condition and _in_matches(value, condition["$nin"]):
            return False
        if "$ne" in condition and _matches_value(value, condition["$ne"]):
            return False
        if "$regex" in condition:
            flags = _re.IGNORECASE if condition.get("$options") == "i" else 0
            if not _re.search(condition["$regex"], str(value or ""), flags):
                return False
        if not _match_range_ops(value, condition):
            return False
    return True


def _match_all(docs: list, query: dict) -> list:
    return [d for d in docs if _match_doc(d, query)]


# ---------------------------------------------------------------------------
# Aggregation pipeline executor
# ---------------------------------------------------------------------------


_REMOVE = object()  # sentinel: field omitted from the output document
_ABSENT = object()  # sentinel: the path reached nothing, so the element contributes nothing


def _traverse_expr_path(value, path: str):
    """One field path as an aggregation expression reads it.

    An array maps the rest of the path over its elements *without* flattening, so a path crossing
    two array levels answers an array of arrays — which is what ``$in`` and ``$size`` then see.
    Query matching flattens instead, which is why this cannot be ``_resolve_dotted``.
    """
    if isinstance(value, list):
        reached = [_traverse_expr_path(element, path) for element in value if isinstance(element, dict)]
        return [item for item in reached if item is not _ABSENT]
    if not isinstance(value, dict):
        return _ABSENT
    head, _, rest = path.partition(".")
    if head not in value:
        return _ABSENT
    return _traverse_expr_path(value[head], rest) if rest else value[head]


def _resolve_expr_path(doc: dict, path: str):
    resolved = _traverse_expr_path(doc, path)
    return None if resolved is _ABSENT else resolved


def _to_number(value):
    """Best-effort numeric coercion for $toDouble / arithmetic; None stays None."""
    if value is None or isinstance(value, bool):
        return None if value is None else value
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _substitute_var(expr, prefix: str, value):
    """Replace ``$$var`` / ``$$var.path`` references with a literal.

    Every other reference is left alone so it still resolves against the root document, which is
    what ``$$CURRENT`` stays bound to inside ``$map``, ``$filter`` and ``$let``.
    """
    if isinstance(expr, str) and (expr == prefix or expr.startswith(f"{prefix}.")):
        tail = expr[len(prefix) :].lstrip(".")
        if not tail:
            return {"$literal": value}
        # A path into a non-document, or into a document that lacks it, is missing on the
        # server: the enclosing document expression omits the field rather than nulling it.
        if not isinstance(value, dict) or not _has_field(value, tail):
            return {"$literal": _REMOVE}
        return {"$literal": _resolve_dotted(value, tail)}
    if isinstance(expr, dict):
        return {k: _substitute_var(v, prefix, value) for k, v in expr.items()}
    if isinstance(expr, list):
        return [_substitute_var(e, prefix, value) for e in expr]
    return expr


def _eval_map(doc: dict, spec: dict):
    items = _eval_expr(doc, spec.get("input"))
    if not isinstance(items, list):
        return None
    prefix = f"$${spec.get('as', 'this')}"
    return [_eval_expr(doc, _substitute_var(spec.get("in"), prefix, item)) for item in items]


def _eval_filter(doc: dict, spec: dict):
    items = _eval_expr(doc, spec.get("input"))
    if not isinstance(items, list):
        return None
    prefix = f"$${spec.get('as', 'this')}"
    return [item for item in items if _eval_bool(doc, _substitute_var(spec.get("cond"), prefix, item))]


def _eval_reduce(doc: dict, spec: dict):
    items = _eval_expr(doc, spec.get("input"))
    if items is None or items is _REMOVE:
        return None
    if not isinstance(items, list):
        raise OperationFailure(f"$reduce requires that 'input' be an array, found: {items}", 40080)
    accumulated = _eval_expr(doc, spec.get("initialValue"))
    for item in items:
        body = _substitute_var(_substitute_var(spec.get("in"), "$$this", item), "$$value", accumulated)
        accumulated = _eval_expr(doc, body)
    return accumulated


def _eval_let(doc: dict, spec: dict):
    body = spec.get("in")
    for var, value_expr in (spec.get("vars") or {}).items():
        body = _substitute_var(body, f"$${var}", _eval_expr(doc, value_expr))
    return _eval_expr(doc, body)


def _eval_expr(doc: dict, expr):
    """Evaluate a MongoDB aggregation expression against a single document.

    Handles the operator subset used by the stats pipelines: $ifNull, $cond,
    $switch, comparison ($eq/$ne/$gt/$gte/$lt/$lte), logical ($and/$or/$in),
    arithmetic ($add/$multiply/$divide/$round), $toDouble, and the $$REMOVE /
    $field / dotted-path / literal cases.
    """
    if isinstance(expr, str):
        if expr == "$$REMOVE":
            return _REMOVE
        if expr == "$$ROOT":
            return doc
        if expr.startswith("$$ROOT."):
            return _resolve_expr_path(doc, expr[len("$$ROOT.") :])
        if expr.startswith("$"):
            return _resolve_expr_path(doc, expr[1:])
        return expr
    if isinstance(expr, list):
        # An array is an expression too: the server evaluates every element, so a field path
        # inside one resolves rather than reaching the document as the literal string "$field".
        return [_eval_expr(doc, element) for element in expr]
    if not isinstance(expr, dict):
        return expr

    if "$literal" in expr:
        return expr["$literal"]
    if "$map" in expr:
        return _eval_map(doc, expr["$map"])
    if "$filter" in expr:
        return _eval_filter(doc, expr["$filter"])
    if "$let" in expr:
        return _eval_let(doc, expr["$let"])
    if "$mergeObjects" in expr:
        merged: dict = {}
        for operand in expr["$mergeObjects"]:
            value = _eval_expr(doc, operand)
            if isinstance(value, dict):
                merged.update(value)
        return merged
    if "$toString" in expr:
        value = _eval_expr(doc, expr["$toString"])
        return None if value is None else str(value)
    if "$dateTrunc" in expr:
        spec = expr["$dateTrunc"]
        return _truncate_date(_eval_expr(doc, spec.get("date")), spec.get("unit", "day"))
    if "$first" in expr:
        return _eval_expr(doc, expr["$first"])
    if "$reduce" in expr:
        return _eval_reduce(doc, expr["$reduce"])
    if "$ifNull" in expr:
        primary, fallback = expr["$ifNull"]
        val = _eval_expr(doc, primary)
        # A path that reached nothing is missing, not null, and $ifNull falls back on both.
        return val if val is not None and val is not _REMOVE else _eval_expr(doc, fallback)
    if "$toDouble" in expr:
        return _to_number(_eval_expr(doc, expr["$toDouble"]))
    if "$split" in expr:
        value, sep = (_eval_expr(doc, e) for e in expr["$split"])
        return str(value).split(str(sep)) if value is not None else None
    if "$arrayElemAt" in expr:
        array, idx = (_eval_expr(doc, e) for e in expr["$arrayElemAt"])
        if not isinstance(array, list):
            return None
        try:
            return array[int(idx)]
        except IndexError:
            return None
    if "$indexOfCP" in expr:
        haystack, needle = (_eval_expr(doc, e) for e in expr["$indexOfCP"])
        return str(haystack).find(str(needle)) if haystack is not None else -1
    if "$size" in expr:
        val = _eval_expr(doc, expr["$size"])
        if not isinstance(val, list):
            # The server fails the whole aggregation here, so a pipeline that
            # forgot an $ifNull must not read as a zero-length array.
            raise TypeError(f"$size requires an array, got {val!r}")
        return len(val)
    if "$setDifference" in expr:
        a, b = (_eval_expr(doc, e) for e in expr["$setDifference"])
        # A null operand answers null rather than an empty array, which is how an unguarded
        # pipeline ends up storing team_ids: null instead of failing.
        if a is None or b is None:
            return None
        if not isinstance(a, list) or not isinstance(b, list):
            raise OperationFailure("both operands of $setDifference must be arrays", 17048)
        out: list = []
        for item in a:
            if item not in b and item not in out:
                out.append(item)
        return out
    if "$objectToArray" in expr:
        value = _eval_expr(doc, expr["$objectToArray"])
        if value is None:
            return None
        if not isinstance(value, dict):
            raise OperationFailure(f"$objectToArray requires a document input, found: {type(value).__name__}")
        return [{"k": key, "v": item} for key, item in value.items()]
    if "$arrayToObject" in expr:
        value = _eval_expr(doc, expr["$arrayToObject"])
        if value is None:
            return None
        if not isinstance(value, list):
            raise OperationFailure(f"$arrayToObject requires an array input, found: {type(value).__name__}")
        # Both the {k, v} and the two-element-array spellings are accepted, last key winning.
        built: dict = {}
        for entry in value:
            if isinstance(entry, dict):
                built[entry["k"]] = entry["v"]
            else:
                built[entry[0]] = entry[1]
        return built
    if "$setUnion" in expr:
        union: list = []
        for operand in expr["$setUnion"]:
            vals = _eval_expr(doc, operand)
            if vals is None:
                return None
            if not isinstance(vals, list):
                raise OperationFailure("All operands of $setUnion must be arrays", 17043)
            for item in vals:
                if item not in union:
                    union.append(item)
        # Measured: the server returns the union in BSON order, unlike $setDifference, which
        # keeps the order of its first operand.
        return sorted(union, key=_bson_sort_key)
    if "$toLower" in expr:
        val = _eval_expr(doc, expr["$toLower"])
        return str(val).lower() if val is not None else None
    if "$cond" in expr:
        cond = expr["$cond"]
        if isinstance(cond, list):
            if_expr, then_expr, else_expr = cond
        else:
            if_expr, then_expr, else_expr = cond["if"], cond["then"], cond["else"]
        branch = then_expr if _eval_bool(doc, if_expr) else else_expr
        return _eval_expr(doc, branch)
    if "$switch" in expr:
        switch = expr["$switch"]
        for branch in switch.get("branches", []):
            if _eval_bool(doc, branch["case"]):
                return _eval_expr(doc, branch["then"])
        return _eval_expr(doc, switch.get("default"))
    if "$add" in expr:
        operands = [_to_number(_eval_expr(doc, e)) for e in expr["$add"]]
        return None if any(v is None for v in operands) else sum(operands)
    if "$multiply" in expr:
        operands = [_to_number(_eval_expr(doc, e)) for e in expr["$multiply"]]
        if any(v is None for v in operands):
            return None
        product = 1.0
        for v in operands:
            product *= v
        return product
    if "$divide" in expr:
        dividend, divisor = (_to_number(_eval_expr(doc, e)) for e in expr["$divide"])
        return None if dividend is None or divisor in (None, 0) else dividend / divisor
    if "$round" in expr:
        spec = expr["$round"]
        value_expr, places = spec if isinstance(spec, list) else (spec, 0)
        value = _to_number(_eval_expr(doc, value_expr))
        return None if value is None else round(value, int(places))

    for op in ("$eq", "$ne", "$gt", "$gte", "$lt", "$lte", "$and", "$or", "$in"):
        if op in expr:
            return _eval_bool(doc, expr)
    for unknown in (k for k in expr if k.startswith("$")):
        raise OperationFailure(f"Unrecognized expression '{unknown}'")
    # Operator-free dict: Mongo treats it as a document expression, so evaluate each value
    # and omit the fields whose expression resolved to missing.
    evaluated = ((k, _eval_expr(doc, v)) for k, v in expr.items())
    return {k: v for k, v in evaluated if v is not _REMOVE}


def _truthy(value) -> bool:
    """Mongo counts only false, null and zero as false — "" and [] are true."""
    if value is None or value is False or value is _REMOVE:
        return False
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    return True


def _eval_bool(doc: dict, expr) -> bool:
    """Evaluate a boolean aggregation expression."""
    if isinstance(expr, bool):
        return expr
    if not isinstance(expr, dict):
        return _truthy(_eval_expr(doc, expr))
    if "$and" in expr:
        return all(_eval_bool(doc, sub) for sub in expr["$and"])
    if "$or" in expr:
        return any(_eval_bool(doc, sub) for sub in expr["$or"])
    if "$in" in expr:
        needle, haystack = expr["$in"]
        return _eval_expr(doc, needle) in (_eval_expr(doc, haystack) or [])
    # Comparison expressions rank across BSON types rather than bracketing to one,
    # so a null operand answers by its position in that order instead of failing,
    # and a bool never equals the number it would coerce to in Python.
    for op, cmp_fn in (("$eq", _op.eq), ("$ne", _op.ne), *_CMP.items()):
        if op in expr:
            a, b = (_eval_expr(doc, e) for e in expr[op])
            return cmp_fn(_bson_sort_key(_naive_utc(a)), _bson_sort_key(_naive_utc(b)))
    return _truthy(_eval_expr(doc, expr))


def _run_project(docs: list, project_spec: dict) -> list:
    """Apply a $project stage, evaluating each field expression per document."""
    # An exclusion-only projection keeps every other field, unlike an inclusion one.
    if project_spec and all(spec in (0, False) for spec in project_spec.values()):
        return [{k: v for k, v in doc.items() if k not in project_spec} for doc in docs]
    out = []
    for doc in docs:
        projected: dict = {}
        if "_id" not in project_spec:
            projected["_id"] = doc.get("_id")
        for field, spec in project_spec.items():
            if spec in (1, True):
                if field in doc:
                    projected[field] = doc[field]
                continue
            if spec in (0, False):
                continue
            val = _eval_expr(doc, spec)
            if val is not _REMOVE:
                projected[field] = val
        out.append(projected)
    return out


def _resolve_field(doc: dict, expr):
    """Resolve a $field reference, dotted path, aggregation expression, or literal."""
    return _eval_expr(doc, expr)


def _accumulator_value(doc: dict, expr):
    """An accumulator input, with a missing field reported as ``_REMOVE``.

    $push and $addToSet contribute nothing for a document that lacks the field, while an
    explicit null is a value they do collect — a distinction ``None`` alone cannot carry.
    """
    value = _eval_expr(doc, expr)
    if value is None and isinstance(expr, str) and expr.startswith("$") and not _has_field(doc, expr.lstrip("$")):
        return _REMOVE
    return value


def _resolve_group_key(doc: dict, id_spec):
    """Resolve the _id expression in a $group stage to a hashable key."""
    if id_spec is None:
        return None
    if isinstance(id_spec, str) and id_spec.startswith("$"):
        return _resolve_dotted(doc, id_spec[1:])
    if isinstance(id_spec, dict):
        if "$dateTrunc" in id_spec:
            return _eval_expr(doc, id_spec)
        resolved = {}
        for k, v in id_spec.items():
            if isinstance(v, dict) and "$dateTrunc" in v:
                resolved[k] = _eval_expr(doc, v)
                continue
            value = _resolve_field(doc, v)
            # Mongo omits a grouping key whose field the document does not carry,
            # rather than setting it to None, so a reader indexing it raises.
            if value is None and isinstance(v, str) and v.startswith("$") and not _has_field(doc, v[1:]):
                continue
            resolved[k] = value
        try:
            return tuple(sorted(resolved.items()))
        except TypeError:
            return str(resolved)
    return id_spec


def _run_group(docs: list, group_spec: dict) -> list:
    id_expr = group_spec.get("_id")
    accumulators = {k: v for k, v in group_spec.items() if k != "_id"}

    groups: dict = {}
    key_order: list = []

    for doc in docs:
        key = _resolve_group_key(doc, id_expr)
        hashable = key if not isinstance(key, dict) else str(key)
        is_new = hashable not in groups
        if is_new:
            groups[hashable] = {"_id_val": key}
            key_order.append(hashable)

        grp = groups[hashable]
        for acc_name, acc_expr in accumulators.items():
            op = next(iter(acc_expr))
            arg = acc_expr[op]
            val = _resolve_field(doc, arg)

            if op == "$sum":
                if is_new:
                    grp[acc_name] = val if isinstance(arg, (int, float)) else (val or 0)
                else:
                    inc = val if isinstance(val, (int, float)) else (1 if not isinstance(arg, (int, float)) else arg)
                    grp[acc_name] = grp.get(acc_name, 0) + inc
            elif op == "$first":
                if is_new:
                    grp[acc_name] = val
            elif op == "$firstN":
                # Keeps the first n evaluations of `input`, so an array-valued input yields a
                # list of arrays rather than n flattened elements.
                bucket = grp.setdefault(acc_name, [])
                if len(bucket) < arg.get("n", 0):
                    bucket.append(_resolve_field(doc, arg.get("input")))
            elif op == "$addToSet":
                # Dedupes by full value equality and accepts documents (unhashable in Python), so
                # back it with a list rather than a set. The server's result order is unspecified;
                # first-seen order keeps the fake deterministic for assertions.
                bucket = grp.setdefault(acc_name, [])
                collected = _accumulator_value(doc, arg)
                if collected is not _REMOVE and not any(_bson_same_value(collected, seen) for seen in bucket):
                    bucket.append(collected)
            elif op == "$avg":
                # Track running (sum, count) over non-null numeric values; finalized below.
                num = _to_number(val)
                acc = grp.setdefault("__avg__", {})
                total, count = acc.get(acc_name, (0.0, 0))
                if num is not None:
                    acc[acc_name] = (total + num, count + 1)
                else:
                    acc.setdefault(acc_name, (total, count))
            elif op == "$push":
                collected = _accumulator_value(doc, arg)
                if collected is not _REMOVE:
                    grp.setdefault(acc_name, []).append(collected)
            elif op in ("$min", "$max"):
                # Null and missing values are skipped unless the whole group is
                # null, and the survivors are ranked across BSON types, so a
                # column holding both dates and strings answers with a date.
                if is_new:
                    grp[acc_name] = None
                cur = grp.get(acc_name)
                beats = _op.lt if op == "$min" else _op.gt
                if val is not None and (cur is None or beats(_bson_sort_key(val), _bson_sort_key(cur))):
                    grp[acc_name] = val

    result = []
    for hashable in key_order:
        state = groups[hashable]
        key_val = state.pop("_id_val")
        avg_acc = state.pop("__avg__", {})
        if isinstance(key_val, tuple):
            key_val = dict(key_val)
        row = {"_id": key_val}
        for k, v in state.items():
            row[k] = list(v) if isinstance(v, set) else v
        for acc_name, (total, count) in avg_acc.items():
            row[acc_name] = (total / count) if count else None
        result.append(row)
    return result


def _run_lookup(docs: list, spec: dict, database: Any) -> list:
    """$lookup, both the localField/foreignField and the let/pipeline forms."""
    if database is None:
        return docs
    foreign_docs = list(database[spec["from"]]._docs.values())
    as_field = spec["as"]
    for doc in docs:
        if "pipeline" in spec:
            # let-vars are visible to the sub-pipeline as "$$name" -> stored under "$name".
            bound = {f"${var}": _eval_expr(doc, expr) for var, expr in (spec.get("let") or {}).items()}
            candidates = [{**bound, **fd} for fd in _copy.deepcopy(foreign_docs)]
            matched = _run_pipeline(candidates, spec["pipeline"], database)
            doc[as_field] = [{k: v for k, v in m.items() if not k.startswith("$")} for m in matched]
        else:
            local = _resolve_dotted(doc, spec["localField"])
            # MongoDB joins an array localField element-wise, and matches a scalar against an array
            # foreignField the same way; a plain == joins nothing and lets the test pass anyway.
            wanted = local if isinstance(local, list) else [local]
            doc[as_field] = [
                _copy.deepcopy(fd)
                for fd in foreign_docs
                if _matches_any(_resolve_dotted(fd, spec["foreignField"]), wanted)
            ]
    return docs


def _matches_any(foreign: Any, wanted: list) -> bool:
    candidates = foreign if isinstance(foreign, list) else [foreign]
    return any(candidate in wanted for candidate in candidates)


def _run_unwind(docs: list, field: str, preserve: bool, index_field: str | None) -> list:
    """$unwind, including the ``{path, preserveNullAndEmptyArrays, includeArrayIndex}`` form.

    A non-array value passes through as one document with a null index, and preserving an
    empty array *drops* the field rather than keeping it empty.
    """
    parts = field.split(".")

    def leaf_container(doc: dict) -> Any:
        node: Any = doc
        for part in parts[:-1]:
            node = node.get(part) if isinstance(node, dict) else None
        return node

    out: list = []
    for doc in docs:
        container = leaf_container(doc)
        leaf = parts[-1]
        values = container.get(leaf) if isinstance(container, dict) else None
        if isinstance(values, list) and values:
            for position, element in enumerate(values):
                exploded = _copy.deepcopy(doc)
                leaf_container(exploded)[leaf] = element
                if index_field:
                    exploded[index_field] = position
                out.append(exploded)
            continue
        if isinstance(values, list) or values is None:
            if not preserve:
                continue
            kept = _copy.deepcopy(doc)
            if isinstance(values, list):
                leaf_container(kept).pop(leaf, None)
            if index_field:
                kept[index_field] = None
            out.append(kept)
            continue
        scalar = _copy.deepcopy(doc)
        if index_field:
            scalar[index_field] = None
        out.append(scalar)
    return out


def _run_pipeline(docs: list, pipeline: list, database: Any = None) -> list:
    results = list(docs)
    for stage in pipeline:
        if "$match" in stage:
            results = _match_all(results, stage["$match"])
        elif "$sort" in stage:
            results = _sort_docs(results, stage["$sort"].items())
        elif "$group" in stage:
            results = _run_group(results, stage["$group"])
        elif "$project" in stage:
            results = _run_project(results, stage["$project"])
        elif "$limit" in stage:
            results = results[: stage["$limit"]]
        elif "$skip" in stage:
            results = results[stage["$skip"] :]
        elif "$unwind" in stage:
            spec = stage["$unwind"]
            spec = {"path": spec} if isinstance(spec, str) else spec
            results = _run_unwind(
                results,
                spec["path"].lstrip("$"),
                bool(spec.get("preserveNullAndEmptyArrays")),
                spec.get("includeArrayIndex"),
            )
        elif "$unset" in stage:
            fields = stage["$unset"]
            for d in results:
                for field in [fields] if isinstance(fields, str) else fields:
                    FakeCollection._unset_dotted(d, field)
        elif "$replaceRoot" in stage:
            results = [_eval_expr(d, stage["$replaceRoot"]["newRoot"]) for d in results]
        elif "$addFields" in stage or "$set" in stage:
            spec = stage.get("$addFields") or stage["$set"]
            for d in results:
                for field, expr in spec.items():
                    value = _eval_expr(d, expr)
                    if value is not _REMOVE:
                        FakeCollection._set_dotted(d, field, value)
        elif "$lookup" in stage:
            results = _run_lookup(results, stage["$lookup"], database)
        elif "$facet" in stage:
            results = [
                {name: _run_pipeline(_copy.deepcopy(results), sub, database) for name, sub in stage["$facet"].items()}
            ]
        elif "$count" in stage:
            results = [{stage["$count"]: len(results)}] if results else []
    return results


# ---------------------------------------------------------------------------
# Cursor types
# ---------------------------------------------------------------------------


class _AsyncIter:
    """Generic async iterator over an in-memory list."""

    def __init__(self, items: list):
        self._items = items
        self._idx = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._idx >= len(self._items):
            raise StopAsyncIteration
        item = self._items[self._idx]
        self._idx += 1
        return item

    async def to_list(self, length=None):
        batch = self._items[self._idx :] if length is None else self._items[self._idx : self._idx + length]
        self._idx += len(batch)
        return batch


class _FakeCursor:
    """Chainable cursor for ``find()``. Supports skip/limit/sort/projection and close()."""

    def __init__(self, docs: dict, query: dict, sort=None, limit: int = 0, skip: int = 0, projection=None):
        self._docs = docs
        self._query = query
        self._sort: list[tuple[str, int]] = list(sort) if sort else []
        self._skip_n = skip
        self._limit_n = limit
        self._projection = projection
        self._remaining: list | None = None

    def skip(self, n: int) -> _FakeCursor:
        self._skip_n = n
        return self

    def limit(self, n: int) -> _FakeCursor:
        self._limit_n = n
        return self

    def sort(self, key_or_list, direction: int = 1) -> _FakeCursor:
        if isinstance(key_or_list, list):
            self._sort = list(key_or_list)
        else:
            self._sort = [(key_or_list, direction)]
        return self

    def _filtered(self) -> list:
        results = _sort_docs([d for d in self._docs.values() if _match_doc(d, self._query)], self._sort)
        results = results[self._skip_n :]
        if self._limit_n:
            results = results[: self._limit_n]
        if self._projection:
            return [_apply_projection(doc, self._projection) for doc in results]
        return results

    def _unread(self) -> list:
        if self._remaining is None:
            self._remaining = self._filtered()
        return self._remaining

    async def to_list(self, length=None) -> list:
        # The server caps the batch at ``length`` and consumes it, so a paging loop terminates here
        # too and a test of a saturated read cannot pass by re-reading the same first page.
        remaining = self._unread()
        batch = list(remaining) if length is None else remaining[:length]
        del remaining[: len(batch)]
        return batch

    def __aiter__(self):
        return self

    async def __anext__(self):
        remaining = self._unread()
        if not remaining:
            raise StopAsyncIteration
        return remaining.pop(0)

    async def close(self) -> None:
        self._remaining = []


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def _copy_projected_path(src: dict, parts: list[str], dst: dict) -> None:
    head = parts[0]
    if head not in src:
        return
    value = src[head]
    if len(parts) == 1:
        dst[head] = _copy.deepcopy(value)
        return
    if isinstance(value, list):
        # Sibling paths sharing an array prefix project into the same elements,
        # so the bucket is filled positionally instead of appended to.
        bucket = dst.setdefault(head, [])
        position = 0
        for element in value:
            if not isinstance(element, dict):
                continue
            if position == len(bucket):
                bucket.append({})
            _copy_projected_path(element, parts[1:], bucket[position])
            position += 1
        return
    if isinstance(value, dict):
        _copy_projected_path(value, parts[1:], dst.setdefault(head, {}))


def _drop_projected_path(node: Any, parts: list[str]) -> None:
    if isinstance(node, list):
        for element in node:
            _drop_projected_path(element, parts)
        return
    head = parts[0]
    if not isinstance(node, dict) or head not in node:
        return
    if len(parts) == 1:
        node.pop(head)
        return
    _drop_projected_path(node[head], parts[1:])


def _apply_projection(doc: dict | None, projection: dict | None) -> dict | None:
    """Trim a document the way the server does, so a too-narrow projection is visible in tests."""
    if doc is None or not projection:
        return doc
    fields = {path: spec for path, spec in projection.items() if path != "_id"}
    if any(spec in (1, True) for spec in fields.values()):
        out: dict = {}
        for path, spec in fields.items():
            if spec in (1, True):
                _copy_projected_path(doc, path.split("."), out)
        if projection.get("_id", 1) not in (0, False) and "_id" in doc:
            out["_id"] = doc["_id"]
        return out
    out = _copy.deepcopy(doc)
    for path in fields:
        _drop_projected_path(out, path.split("."))
    if projection.get("_id") in (0, False):
        out.pop("_id", None)
    return out


def _conflicting_prefix(left: str, right: str) -> str | None:
    """The path two update paths collide on, or None when they are disjoint.

    Mongo compares segment by segment, so ``a`` contains ``a.b`` while ``ab`` and ``a.1`` and
    ``a.10`` are all distinct. ``$[ident]`` is an ordinary segment, which is why two array
    filters may update sibling elements of one array in a single write.
    """
    left_parts, right_parts = left.split("."), right.split(".")
    shared = min(len(left_parts), len(right_parts))
    if left_parts[:shared] != right_parts[:shared]:
        return None
    return ".".join(left_parts[:shared])


def assert_no_path_conflict(update: dict | list) -> None:
    """Refuse two modifiers whose paths overlap, as the server does with code 40.

    This is the divergence that matters most for array work: a sync that both $pulls its own
    owners and $addToSets the new ones in one update is rejected in production, so a fake that
    applied both would green-light a write that can never land.

    The server parses the update before it looks for a document, so this runs at the call and
    not on the applied path: a filter that matched nothing still reports the conflict.
    """
    if isinstance(update, list):
        return
    seen: list[str] = []
    for payload in update.values():
        if not isinstance(payload, dict):
            continue
        for path in payload:
            for earlier in seen:
                prefix = _conflicting_prefix(earlier, path)
                if prefix is not None:
                    raise OperationFailure(f"Updating the path '{path}' would create a conflict at '{prefix}'", 40)
            seen.append(path)


def _add_to_set_values(value: Any) -> list:
    """The elements one $addToSet contributes.

    Only a document whose *first* key is ``$each`` is a batch; ``{"x": 1, "$each": [...]}`` is
    stored as a literal, so the unwrapping cannot be a plain membership test.
    """
    if isinstance(value, dict) and next(iter(value), None) == "$each":
        if len(value) > 1:
            raise OperationFailure(f"Found unexpected fields after $each in $addToSet: {value}", 2)
        each = value["$each"]
        if not isinstance(each, list):
            raise OperationFailure(
                f"The argument to $each in $addToSet must be an array but it was of type {type(each).__name__}", 14
            )
        return each
    return [value]


def _matched_key(docs: dict, query: dict) -> Any:
    """Return the key of the first doc matching ``query`` (full operator support)."""
    for key, doc in docs.items():
        if _match_doc(doc, query):
            return key
    return None


class FakeCollection:
    """In-process collection covering the Motor API surface that the app uses."""

    def __init__(self, db: Any = None, unique_keys: list[tuple[str, ...]] | None = None):
        self._docs: dict = {}
        self._db = db
        self._unique_keys: list[tuple[str, ...]] = list(unique_keys or [])
        self.created_indexes: list[str | tuple[str, ...]] = []

    # -- writes -----------------------------------------------------------

    def _duplicate_key(self, doc: dict) -> str | None:
        """The unique index a document collides on, or None.

        Sparse semantics: an entry is indexed unless every indexed field is ABSENT. An explicit
        null is a value and still collides — which is why init_db rebuilds the sparse compound
        project indexes with a partialFilterExpression (see _migrate_project_indexes), Pydantic
        serialising None being exactly how those nulls arrive.
        """
        if doc.get("_id") in self._docs:
            return "_id"
        for fields in self._unique_keys:
            if all(field not in doc for field in fields):
                continue
            values = tuple(doc.get(field) for field in fields)
            for existing in self._docs.values():
                if all(field not in existing for field in fields):
                    continue
                if tuple(existing.get(field) for field in fields) == values:
                    return ", ".join(fields)
        return None

    async def insert_one(self, doc: dict):
        from pymongo.errors import DuplicateKeyError

        collision = self._duplicate_key(doc)
        if collision is not None:
            raise DuplicateKeyError(f"E11000 duplicate key error: {collision}")
        # The driver stamps the _id onto the caller's document, which is how code that needs the
        # new id reads it back without a round trip.
        doc.setdefault("_id", ObjectId())
        self._docs[doc["_id"]] = _bsonify(doc)
        result = MagicMock()
        result.inserted_id = doc["_id"]
        return result

    async def insert_many(self, docs: list, ordered: bool = True):
        from pymongo.errors import BulkWriteError

        inserted = []
        write_errors = []
        for index, doc in enumerate(docs):
            collision = self._duplicate_key(doc)
            if collision is not None:
                # Mirror Mongo's duplicate-key semantics so idempotent-insert paths are testable.
                write_errors.append(
                    {"index": index, "code": 11000, "errmsg": f"E11000 duplicate key error: {collision}"}
                )
                if ordered:
                    break
                continue
            doc.setdefault("_id", ObjectId())
            self._docs[doc["_id"]] = _bsonify(doc)
            inserted.append(doc["_id"])
        if write_errors:
            raise BulkWriteError({"writeErrors": write_errors, "nInserted": len(inserted)})
        result = MagicMock()
        result.inserted_ids = inserted
        return result

    def _insert_upserted(self, query: dict, update: dict | list) -> dict:
        """The document an upsert inserts once its filter matched nothing.

        The server builds it from the filter's equality terms plus the update and then
        *inserts* it, so a filter that missed on a non-_id condition collides on E11000
        instead of overwriting the document that is already there. The distributed lock
        depends on exactly that: a held lock fails the expiry condition, and the E11000
        is what tells the second holder it lost the race.
        """
        from pymongo.errors import DuplicateKeyError

        doc = {k: v for k, v in query.items() if not isinstance(v, dict) and not k.startswith("$")}
        if isinstance(update, list):
            self._apply_update(doc, update)
        else:
            doc.update(update.get(_SET_ON_INSERT, {}))
            self._apply_update(doc, update, skip_set_on_insert=True)
        doc.setdefault("_id", ObjectId())
        collision = self._duplicate_key(doc)
        if collision is not None:
            raise DuplicateKeyError(f"E11000 duplicate key error: {collision}")
        self._docs[doc["_id"]] = _bsonify(doc)
        return self._docs[doc["_id"]]

    async def update_one(self, query, update, array_filters=None, upsert: bool = False):
        assert_no_path_conflict(update)
        matched = _matched_key(self._docs, query)
        modified = 0
        if matched is not None:
            before = _copy.deepcopy(self._docs[matched])
            self._apply_update(self._docs[matched], update, array_filters=array_filters)
            modified = int(not _bson_identical(self._docs[matched], before))
        elif upsert:
            self._insert_upserted(query, update)
        result = MagicMock()
        result.modified_count = modified
        # A conditional write tells a filter miss apart from a no-op on matched_count alone.
        result.matched_count = int(matched is not None)
        return result

    async def update_many(self, query, update, array_filters=None, upsert: bool = False):
        assert_no_path_conflict(update)
        matched = [k for k, doc in self._docs.items() if _match_doc(doc, query)]
        modified = 0
        for k in matched:
            before = _copy.deepcopy(self._docs[k])
            self._apply_update(self._docs[k], update, array_filters=array_filters)
            # Real Mongo does not count a $set that changes nothing.
            modified += not _bson_identical(self._docs[k], before)
        if not matched and upsert:
            self._insert_upserted(query, update)
        result = MagicMock()
        result.modified_count = modified
        result.matched_count = len(matched)
        return result

    def with_options(self, **_kwargs) -> FakeCollection:
        # Read-preference / write-concern variations are no-ops in-process.
        return self

    async def find_one_and_update(self, query, update, return_document: bool = False, upsert: bool = False, **_kwargs):
        assert_no_path_conflict(update)
        matched = _matched_key(self._docs, query)
        if matched is None:
            if not upsert:
                return None
            doc = self._insert_upserted(query, update)
            return doc if return_document else None
        before = dict(self._docs[matched])
        self._apply_update(self._docs[matched], update)
        return self._docs[matched] if return_document else before

    @staticmethod
    def _apply_update(
        target: dict, update: dict | list, skip_set_on_insert: bool = False, array_filters: list | None = None
    ) -> None:
        if isinstance(update, list):
            FakeCollection._apply_update_pipeline(target, update)
            return
        filters = _array_filter_predicates(array_filters)
        update = _bsonify(update)
        for op, payload in update.items():
            if op == "$set":
                for k, v in payload.items():
                    FakeCollection._set_dotted(target, k, v, filters)
            elif op == "$setOnInsert":
                # only applied when called outside upsert insert path
                for k, v in payload.items() if not skip_set_on_insert else ():
                    target.setdefault(k, v)
            elif op == "$unset":
                for field in payload:
                    FakeCollection._unset_dotted(target, field)
            elif op == "$inc":
                for field, delta in payload.items():
                    parent, leaf = FakeCollection._resolve_parent(target, field)
                    parent[leaf] = parent.get(leaf, 0) + delta
            elif op == "$addToSet":
                for field, value in payload.items():
                    bucket = FakeCollection._array_for_update(target, field, "$addToSet")
                    for element in _add_to_set_values(value):
                        if not any(_bson_same_value(element, existing) for existing in bucket):
                            bucket.append(element)
            elif op == "$push":
                for field, value in payload.items():
                    FakeCollection._array_for_update(target, field, "$push").append(value)
            elif op == "$pull":
                for field, condition in payload.items():
                    FakeCollection._pull_from(target, field, condition)
            else:
                raise OperationFailure(f"Unknown modifier: {op}")

    @staticmethod
    def _apply_update_pipeline(target: dict, pipeline: list) -> None:
        """Aggregation-pipeline update form: each stage rewrites the document in place."""
        staged = _run_pipeline([_copy.deepcopy(target)], pipeline)
        # _id is immutable, so a $project or $replaceRoot that dropped it keeps the original.
        identifier = target.get("_id")
        target.clear()
        if staged:
            target.update(_bsonify(staged[0]))
        if identifier is not None:
            target["_id"] = identifier

    @staticmethod
    def _array_for_update(target: dict, dotted_key: str, op_name: str) -> list:
        """The array an array modifier writes to, created empty when the path is absent.
        A non-array value already sitting there fails the update, as the server does."""
        parent, leaf = FakeCollection._resolve_parent(target, dotted_key)
        present = leaf < len(parent) if isinstance(parent, list) else leaf in parent
        if not present:
            parent[leaf] = []
        current = parent[leaf]
        if not isinstance(current, list):
            if op_name == "$push":
                raise OperationFailure(
                    f"The field '{dotted_key}' must be an array but is of type {_bson_type_name(current)}", 2
                )
            raise OperationFailure(
                f"Cannot apply $addToSet to non-array field. Field named '{dotted_key}' "
                f"has non-array type {_bson_type_name(current)}",
                2,
            )
        return current

    @staticmethod
    def _pull_from(target: dict, dotted_key: str, condition: Any) -> None:
        """$pull, which leaves a document that lacks the path completely alone rather than
        creating an empty array there, and refuses a path holding a non-array."""
        parts = dotted_key.split(".")
        node: Any = target
        for part in parts[:-1]:
            if isinstance(node, dict):
                node = node.get(part)
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                return
        leaf: Any = parts[-1]
        if isinstance(node, list):
            leaf = int(leaf)
            if leaf >= len(node):
                return
        elif not isinstance(node, dict) or leaf not in node:
            return
        current = node[leaf]
        if not isinstance(current, list):
            raise OperationFailure("Cannot apply $pull to a non-array value", 2)
        node[leaf] = [item for item in current if not _pull_matches(item, condition)]

    @staticmethod
    def _resolve_parent(target: dict, dotted_key: str) -> tuple[Any, Any]:
        """Walk (creating) nested containers so dotted update paths behave like real Mongo.

        A numeric segment indexes into a list, so ``members.1.role`` rewrites that element
        instead of hanging a ``{"1": ...}`` dict off the document.
        """
        parts = dotted_key.split(".")
        node: Any = target
        for part in parts[:-1]:
            node = _descend_for_update(node, part)
        leaf = parts[-1]
        return node, int(leaf) if isinstance(node, list) else leaf

    @staticmethod
    def _unset_dotted(target: dict, dotted_key: str) -> None:
        """Drop a (possibly nested) field. Unlike $set, a missing path creates nothing."""
        parts = dotted_key.split(".")
        node: Any = target
        for part in parts[:-1]:
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, dict):
            node.pop(parts[-1], None)

    @staticmethod
    def _set_dotted(target: dict, dotted_key: str, value, filters: dict | None = None) -> None:
        if "$[" not in dotted_key:
            parent, leaf = FakeCollection._resolve_parent(target, dotted_key)
            parent[leaf] = value
            return
        FakeCollection._set_through_arrays(target, dotted_key.split("."), value, filters or {})

    @staticmethod
    def _set_through_arrays(node, parts: list[str], value, filters: dict) -> None:
        """Apply a positional array update path (``a.$[ident].b`` / ``a.$[].b``)."""
        part = parts[0]
        if part.startswith("$["):
            if not isinstance(node, list):
                return
            predicate = filters.get(part[2:-1])
            for item in node:
                if predicate is None or _match_doc(item, predicate):
                    FakeCollection._set_through_arrays(item, parts[1:], value, filters)
            return
        if len(parts) == 1:
            node[part] = value
            return
        child = node.get(part)
        if child is None:
            child = {}
            node[part] = child
        FakeCollection._set_through_arrays(child, parts[1:], value, filters)

    async def delete_one(self, query):
        await asyncio.sleep(0)
        matched = _matched_key(self._docs, query)
        if matched is not None:
            del self._docs[matched]
        result = MagicMock()
        result.deleted_count = 1 if matched is not None else 0
        return result

    async def delete_many(self, query):
        await asyncio.sleep(0)
        keys = [k for k, doc in self._docs.items() if _match_doc(doc, query)]
        for k in keys:
            del self._docs[k]
        result = MagicMock()
        result.deleted_count = len(keys)
        return result

    async def bulk_write(self, ops, ordered: bool = True):
        modified = 0
        matched = 0
        upserted = 0
        for op in ops:
            flt = op._filter
            upd = op._doc
            upsert = op._upsert
            assert_no_path_conflict(upd)
            matched_keys = [key for key, doc in self._docs.items() if _match_doc(doc, flt)]
            if matched_keys:
                # UpdateMany touches every match; UpdateOne only the first (Mongo semantics).
                if type(op).__name__ != "UpdateMany":
                    matched_keys = matched_keys[:1]
                matched += len(matched_keys)
                for key in matched_keys:
                    before = _copy.deepcopy(self._docs[key])
                    self._apply_update(self._docs[key], upd)
                    modified += not _bson_identical(self._docs[key], before)
            elif upsert:
                upserted += 1
                doc: dict = {}
                doc.update(upd.get(_SET_ON_INSERT, {}))
                doc.update(upd.get("$set", {}))
                if "_id" not in doc:
                    # Fall back to a deterministic composite key from filter fields
                    # (matches the unique-index strategy in crypto-asset upserts).
                    if "_id" in upd.get("$set", {}):
                        doc["_id"] = upd["$set"]["_id"]
                    else:
                        ident_parts = [str(flt.get(f, "")) for f in ("project_id", "scan_id", "bom_ref")]
                        doc["_id"] = ":".join(p for p in ident_parts if p) or str(len(self._docs))
                self._docs[doc["_id"]] = _bsonify(doc)
        result = MagicMock()
        result.modified_count = modified
        result.matched_count = matched
        result.upserted_count = upserted
        return result

    async def create_index(self, keys, **kwargs):
        if kwargs.get("unique"):
            fields = [keys] if isinstance(keys, str) else [key for key, _direction in keys]
            self._unique_keys.append(tuple(fields))
        if isinstance(keys, str):
            self.created_indexes.append(keys)
        else:
            self.created_indexes.append(tuple(key for key, _direction in keys))

    async def index_information(self):
        return {}

    async def drop_index(self, *args, **kwargs):
        return None

    # -- reads ------------------------------------------------------------

    async def find_one(self, query, projection=None, sort=None):
        # Fast path for _id-only queries (common in repository code)
        if set(query.keys()) == {"_id"} and not isinstance(query["_id"], dict):
            return _apply_projection(self._docs.get(query["_id"]), projection)
        if sort:
            # Mirror real Mongo: apply the sort, then return the first match.
            matches = _sort_docs([doc for doc in self._docs.values() if _match_doc(doc, query)], sort)
            return _apply_projection(matches[0], projection) if matches else None
        for doc in self._docs.values():
            if _match_doc(doc, query):
                return _apply_projection(doc, projection)
        return None

    async def count_documents(self, query, limit: int = 0, **_kwargs):
        count = sum(1 for doc in self._docs.values() if _match_doc(doc, query))
        return min(count, limit) if limit else count

    async def distinct(self, field: str, filter: dict | None = None):
        seen: list = []
        for doc in self._docs.values():
            if filter and not _match_doc(doc, filter):
                continue
            val = doc.get(field)
            if val not in seen:
                seen.append(val)
        return seen

    def find(self, query=None, projection=None, **kwargs) -> _FakeCursor:
        return _FakeCursor(
            self._docs,
            query or {},
            sort=kwargs.get("sort"),
            limit=kwargs.get("limit", 0),
            skip=kwargs.get("skip", 0),
            projection=projection,
        )

    def aggregate(self, pipeline: list, **_kwargs) -> _AsyncIter:
        # ``allowDiskUse`` (and any other server-side option) is a no-op in-process.
        return _AsyncIter(_run_pipeline(_copy.deepcopy(list(self._docs.values())), pipeline, self._db))


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


class FakeDatabase:
    """In-process database. Collections are created on demand via attribute or
    item access, so consumer code that does ``db.foo`` or ``db["bar"]`` always
    gets a stable per-instance collection."""

    def __init__(self):
        # Pre-create the common collections so they exist on the same instance
        # even before any access — helps tests that seed via ``db.projects._docs``.
        for name in (
            "projects",
            "scans",
            "findings",
            "dependencies",
            "system_settings",
            "crypto_policies",
            "crypto_assets",
            "teams",
            "users",
        ):
            object.__setattr__(self, name, FakeCollection(self))
        # Every release write runs against the constraint production runs against, so a test
        # cannot prove idempotence on a filter the server would never have needed.
        object.__setattr__(self, "releases", FakeCollection(self, unique_keys=[RELEASES_UPSERT_KEY_FIELDS]))

    def __getattr__(self, name: str) -> FakeCollection:
        # Auto-vivify collections so repositories that touch unexpected ones
        # don't AttributeError before the test even runs.
        col = FakeCollection(self)
        object.__setattr__(self, name, col)
        return col

    def __getitem__(self, name: str) -> FakeCollection:
        return getattr(self, name)
