"""In-process fake MongoDB for tests.

Consolidates what used to be two parallel implementations (`tests/unit/conftest.py`
and `tests/integration/conftest.py`) into a single source of truth. Supports the
operators that the application code actually uses — extend here, not in conftest.

Supported query operators
-------------------------
- Equality and dotted paths (``members.user_id`` recurses into list elements)
- ``$in``, ``$nin``, ``$ne``, ``$exists``
- ``$regex`` (with ``$options: "i"`` for case-insensitive)
- Range: ``$gt``, ``$gte``, ``$lt``, ``$lte``
- Logical: top-level ``$or``, ``$and``

Supported update operators
--------------------------
- ``$set``, ``$setOnInsert``, ``$inc``, ``$addToSet``

Server-side behaviour that tests rely on
----------------------------------------
- Projections in ``find``/``find_one``, inclusion and exclusion, dotted paths
  included, so a too-narrow projection surfaces here instead of in production.
- BSON datetimes: a written aware datetime is stored (and read back) as naive
  UTC, and an aware query value is normalised before comparison, matching what
  the driver puts on the wire.
- Cross-type BSON ordering: sorts, ``$min`` and ``$max`` rank a mixed column
  (missing < number < string < date) instead of raising, while a range query
  brackets to its bound's type and skips the other types outright.
- ``$group`` drops a grouping key the document does not carry rather than
  binding it to null.
- Only false, null and zero are false to ``$cond``/``$switch``; ``""`` and
  ``[]`` are true.

Supported aggregation stages
----------------------------
- ``$match``, ``$sort``, ``$group``, ``$project``, ``$limit``, ``$unwind``
- ``$group`` accumulators: ``$sum``, ``$avg``, ``$first``, ``$min``, ``$max``,
  ``$addToSet``, ``$push``
- ``$dateTrunc`` truncates to the start of the unit (day/week/month/year; week
  starts Sunday, matching MongoDB's default), in both expressions and
  ``$group._id``, so trend bucketing is exercised end-to-end.

Supported aggregation expression operators (in ``$project`` / accumulator args)
------------------------------------------------------------------------------
- ``$ifNull``, ``$cond``, ``$switch``, ``$toDouble``, ``$toLower``
- Comparison: ``$eq``, ``$ne``, ``$gt``, ``$gte``, ``$lt``, ``$lte``
- Logical: ``$and``, ``$or``
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


# ---------------------------------------------------------------------------
# BSON value semantics
# ---------------------------------------------------------------------------


def _naive_utc(value: Any) -> Any:
    """BSON has no offsets: an aware datetime is stored (and read back) as naive UTC."""
    if isinstance(value, _datetime) and value.tzinfo is not None:
        return value.astimezone(_timezone.utc).replace(tzinfo=None)
    return value


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


def _sort_docs(docs: list, sort_spec) -> list:
    """Sort in place by a ``[(field, direction)]`` spec, using BSON ordering."""
    for key, direction in reversed(list(sort_spec)):
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
        elif value == candidate:
            return True
    return False


def _match_doc(doc: dict, query: dict) -> bool:
    """Return True if doc matches a MongoDB query."""
    for key, condition in query.items():
        if key == "$or":
            if not any(_match_doc(doc, sub) for sub in condition):
                return False
            continue
        if key == "$and":
            if not all(_match_doc(doc, sub) for sub in condition):
                return False
            continue
        if key == "$expr":
            # Unsupported before: an unrecognised operator fell through as "matches".
            if not _eval_bool(doc, condition):
                return False
            continue

        value = _resolve_dotted(doc, key)
        # Dotted path landed on a list (e.g. members.user_id): any element matching
        # equality/$in counts as a hit (mirrors real Mongo semantics).
        if isinstance(value, list) and not isinstance(condition, dict):
            if condition in value:
                continue
            return False
        if isinstance(condition, dict):
            if "$exists" in condition:
                field_present = _resolve_dotted(doc, key) is not None or key in doc
                if bool(condition["$exists"]) != field_present:
                    return False
            # For $in/$nin/$ne, when the dotted path landed on a list (array of
            # sub-docs flattened by _resolve_dotted), Mongo treats it as
            # "any element matches" — broadcast the operator across the list.
            if "$in" in condition:
                allowed = condition["$in"]
                if isinstance(value, list):
                    if not any(_in_allowed(v, allowed) for v in value):
                        return False
                elif not _in_allowed(value, allowed):
                    return False
            if "$nin" in condition:
                disallowed = condition["$nin"]
                if isinstance(value, list):
                    if any(v in disallowed for v in value):
                        return False
                elif value in disallowed:
                    return False
            if "$ne" in condition:
                ne_val = condition["$ne"]
                if isinstance(value, list):
                    if ne_val in value:
                        return False
                elif value == ne_val:
                    return False
            if "$regex" in condition:
                flags = _re.IGNORECASE if condition.get("$options") == "i" else 0
                if not _re.search(condition["$regex"], str(value or ""), flags):
                    return False
            if not _match_range_ops(value, condition):
                return False
        else:
            if _naive_utc(value) != _naive_utc(condition):
                return False
    return True


def _match_all(docs: list, query: dict) -> list:
    return [d for d in docs if _match_doc(d, query)]


# ---------------------------------------------------------------------------
# Aggregation pipeline executor
# ---------------------------------------------------------------------------


_REMOVE = object()  # sentinel: field omitted from the output document


def _to_number(value):
    """Best-effort numeric coercion for $toDouble / arithmetic; None stays None."""
    if value is None or isinstance(value, bool):
        return None if value is None else value
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bind_map_var(expr, item, prefix: str):
    """Resolve ``$$var``/``$$var.path`` references inside a $map ``in`` expression."""
    if isinstance(expr, str) and expr.startswith(prefix):
        tail = expr[len(prefix) :].lstrip(".")
        return _resolve_dotted(item, tail) if tail else item
    if isinstance(expr, dict):
        return {k: _bind_map_var(v, item, prefix) for k, v in expr.items()}
    if isinstance(expr, list):
        return [_bind_map_var(e, item, prefix) for e in expr]
    return _eval_expr(item, expr) if isinstance(item, dict) else expr


def _eval_map(doc: dict, spec: dict):
    items = _eval_expr(doc, spec.get("input"))
    if not isinstance(items, list):
        return []
    prefix = f"$${spec.get('as', 'this')}"
    return [_bind_map_var(spec.get("in"), item, prefix) for item in items]


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
        if expr.startswith("$"):
            return _resolve_dotted(doc, expr[1:])
        return expr
    if not isinstance(expr, dict):
        return expr

    if "$map" in expr:
        return _eval_map(doc, expr["$map"])
    if "$dateTrunc" in expr:
        spec = expr["$dateTrunc"]
        return _truncate_date(_eval_expr(doc, spec.get("date")), spec.get("unit", "day"))
    if "$first" in expr:
        return _eval_expr(doc, expr["$first"])
    if "$ifNull" in expr:
        primary, fallback = expr["$ifNull"]
        val = _eval_expr(doc, primary)
        return val if val is not None else _eval_expr(doc, fallback)
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
        a = a if isinstance(a, list) else []
        b = b if isinstance(b, list) else []
        out: list = []
        for item in a:
            if item not in b and item not in out:
                out.append(item)
        return out
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
    # Operator-free dict: Mongo treats it as a document expression, so evaluate each value.
    if expr and not any(k.startswith("$") for k in expr):
        return {k: _eval_expr(doc, v) for k, v in expr.items()}
    return expr


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
            elif op == "$addToSet":
                # Real $addToSet dedupes by full value equality and accepts
                # documents (unhashable in Python). Back it with a list +
                # membership check so dict elements (e.g. slimmed details) work,
                # falling back from a set only when needed.
                bucket = grp.setdefault(acc_name, [])
                if val is not None and val not in bucket:
                    bucket.append(val)
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
                if val is not _REMOVE:
                    grp.setdefault(acc_name, []).append(val)
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
            doc[as_field] = [
                _copy.deepcopy(fd) for fd in foreign_docs if _resolve_dotted(fd, spec["foreignField"]) == local
            ]
    return docs


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
            field_expr = stage["$unwind"]
            field = field_expr.lstrip("$") if isinstance(field_expr, str) else field_expr
            parts = field.split(".")
            unwound = []
            for d in results:
                parent: Any = d
                for p in parts[:-1]:
                    parent = parent.get(p) if isinstance(parent, dict) else None
                values = parent.get(parts[-1]) if isinstance(parent, dict) else None
                if isinstance(values, list):
                    for v in values:
                        new_d = _copy.deepcopy(d)
                        target = new_d
                        for p in parts[:-1]:
                            target = target[p]
                        target[parts[-1]] = v
                        unwound.append(new_d)
                elif values is not None:
                    unwound.append(d)
            results = unwound
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
        return self._items if length is None else self._items[:length]


class _FakeCursor:
    """Chainable cursor for ``find()``. Supports skip/limit/sort/projection."""

    def __init__(self, docs: dict, query: dict, sort=None, limit: int = 0, skip: int = 0, projection=None):
        self._docs = docs
        self._query = query
        self._sort: list[tuple[str, int]] = list(sort) if sort else []
        self._skip_n = skip
        self._limit_n = limit
        self._projection = projection
        self._iter = None

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

    async def to_list(self, length=None) -> list:
        return self._filtered()

    def __aiter__(self):
        self._iter = iter(self._filtered())
        return self

    async def __anext__(self):
        try:
            return next(self._iter)  # type: ignore[arg-type]
        except StopIteration:
            raise StopAsyncIteration


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


def _matched_key(docs: dict, query: dict) -> Any:
    """Return the key of the first doc matching ``query`` (full operator support)."""
    for key, doc in docs.items():
        if _match_doc(doc, query):
            return key
    return None


class FakeCollection:
    """In-process collection covering the Motor API surface that the app uses."""

    def __init__(self, db: Any = None):
        self._docs: dict = {}
        # $lookup needs to reach sibling collections.
        self._db = db
        # Unique-index field tuples declared via create_index(..., unique=True).
        self._unique_keys: list[tuple[str, ...]] = []

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
        key = doc.get("_id") or str(len(self._docs))
        self._docs[key] = _bsonify(doc)
        result = MagicMock()
        result.inserted_id = key
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
            key = doc.get("_id") or str(len(self._docs))
            self._docs[key] = _bsonify(doc)
            inserted.append(key)
        if write_errors:
            raise BulkWriteError({"writeErrors": write_errors, "nInserted": len(inserted)})
        result = MagicMock()
        result.inserted_ids = inserted
        return result

    def _insert_upserted(self, query: dict, update: dict) -> dict:
        """The document an upsert inserts once its filter matched nothing.

        The server builds it from the filter's equality terms plus the update and then
        *inserts* it, so a filter that missed on a non-_id condition collides on E11000
        instead of overwriting the document that is already there. The distributed lock
        depends on exactly that: a held lock fails the expiry condition, and the E11000
        is what tells the second holder it lost the race.
        """
        from pymongo.errors import DuplicateKeyError

        doc = {k: v for k, v in query.items() if not isinstance(v, dict) and not k.startswith("$")}
        doc.update(update.get(_SET_ON_INSERT, {}))
        self._apply_update(doc, update, skip_set_on_insert=True)
        doc["_id"] = doc.get("_id") or str(len(self._docs))
        collision = self._duplicate_key(doc)
        if collision is not None:
            raise DuplicateKeyError(f"E11000 duplicate key error: {collision}")
        self._docs[doc["_id"]] = _bsonify(doc)
        return self._docs[doc["_id"]]

    async def update_one(self, query, update, upsert: bool = False):
        matched = _matched_key(self._docs, query)
        modified = 0
        if matched is not None:
            before = _copy.deepcopy(self._docs[matched])
            self._apply_update(self._docs[matched], update)
            modified = int(self._docs[matched] != before)
        elif upsert:
            self._insert_upserted(query, update)
        result = MagicMock()
        result.modified_count = modified
        return result

    async def update_many(self, query, update, array_filters=None, upsert: bool = False):
        matched = [k for k, doc in self._docs.items() if _match_doc(doc, query)]
        modified = 0
        for k in matched:
            before = _copy.deepcopy(self._docs[k])
            self._apply_update(self._docs[k], update, array_filters=array_filters)
            # Real Mongo does not count a $set that changes nothing.
            modified += self._docs[k] != before
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
        target: dict, update: dict, skip_set_on_insert: bool = False, array_filters: list | None = None
    ) -> None:
        filters = _array_filter_predicates(array_filters)
        update = _bsonify(update)
        for op, payload in update.items():
            if op == "$set":
                for k, v in payload.items():
                    FakeCollection._set_dotted(target, k, v, filters)
            elif op == "$setOnInsert" and not skip_set_on_insert:
                # only applied when called outside upsert insert path
                for k, v in payload.items():
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
                    bucket = target.setdefault(field, [])
                    if value not in bucket:
                        bucket.append(value)

    @staticmethod
    def _resolve_parent(target: dict, dotted_key: str) -> tuple[dict, str]:
        """Walk (creating) nested dicts so dotted update paths behave like real Mongo."""
        parts = dotted_key.split(".")
        node = target
        for part in parts[:-1]:
            nxt = node.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                node[part] = nxt
            node = nxt
        return node, parts[-1]

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
        for op in ops:
            flt = op._filter
            upd = op._doc
            upsert = op._upsert
            matched_keys = [key for key, doc in self._docs.items() if _match_doc(doc, flt)]
            if matched_keys:
                # UpdateMany touches every match; UpdateOne only the first (Mongo semantics).
                if type(op).__name__ != "UpdateMany":
                    matched_keys = matched_keys[:1]
                for key in matched_keys:
                    self._apply_update(self._docs[key], upd)
                    modified += 1
            elif upsert:
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
        return result

    async def create_index(self, keys, **kwargs):
        if kwargs.get("unique"):
            fields = [keys] if isinstance(keys, str) else [key for key, _direction in keys]
            self._unique_keys.append(tuple(fields))

    async def index_information(self):
        # No pre-existing indexes in the in-process fake.
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

    def __getattr__(self, name: str) -> FakeCollection:
        # Auto-vivify collections so repositories that touch unexpected ones
        # don't AttributeError before the test even runs.
        col = FakeCollection(self)
        object.__setattr__(self, name, col)
        return col

    def __getitem__(self, name: str) -> FakeCollection:
        return getattr(self, name)
