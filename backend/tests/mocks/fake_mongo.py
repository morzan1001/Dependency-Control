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

Supported aggregation stages
----------------------------
- ``$match``, ``$sort``, ``$group``, ``$project``, ``$limit``, ``$unwind``
- ``$group`` accumulators: ``$sum``, ``$avg``, ``$first``, ``$min``, ``$max``,
  ``$addToSet``, ``$push``
- ``$dateTrunc`` in ``$group._id`` is accepted but not bucket-rounded
  (returns the raw date value), so trend endpoints emit a single bucket.

Supported aggregation expression operators (in ``$project`` / accumulator args)
------------------------------------------------------------------------------
- ``$ifNull``, ``$cond``, ``$switch``, ``$toDouble``
- Comparison: ``$eq``, ``$ne``, ``$gt``, ``$gte``, ``$lt``, ``$lte``
- Logical: ``$and``, ``$or``
- ``$$REMOVE`` (field is omitted; mirrors Mongo's $push semantics)
"""

from __future__ import annotations

import asyncio
import operator as _op
import re as _re
from typing import Any
from unittest.mock import MagicMock

_SET_ON_INSERT = "$setOnInsert"
_CMP = {"$lt": _op.lt, "$lte": _op.le, "$gt": _op.gt, "$gte": _op.ge}


# ---------------------------------------------------------------------------
# Query matching helpers
# ---------------------------------------------------------------------------


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
            try:
                if not cmp_fn(value, ops_dict[op_key]):
                    return False
            except TypeError:
                return False
    return True


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
                    if not any(v in allowed for v in value):
                        return False
                elif value not in allowed:
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
            if value != condition:
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


def _eval_expr(doc: dict, expr):
    """Evaluate a MongoDB aggregation expression against a single document.

    Handles the operator subset used by the stats pipelines: $ifNull, $cond,
    $switch, comparison ($eq/$ne/$gt/$gte/$lt/$lte), logical ($and/$or),
    $toDouble, and the $$REMOVE / $field / dotted-path / literal cases.
    """
    if isinstance(expr, str):
        if expr == "$$REMOVE":
            return _REMOVE
        if expr.startswith("$"):
            return _resolve_dotted(doc, expr[1:])
        return expr
    if not isinstance(expr, dict):
        return expr

    if "$dateTrunc" in expr:
        # Bucket rounding intentionally skipped — return raw date value.
        return _eval_expr(doc, expr["$dateTrunc"].get("date"))
    if "$first" in expr:
        return _eval_expr(doc, expr["$first"])
    if "$ifNull" in expr:
        primary, fallback = expr["$ifNull"]
        val = _eval_expr(doc, primary)
        return val if val is not None else _eval_expr(doc, fallback)
    if "$toDouble" in expr:
        return _to_number(_eval_expr(doc, expr["$toDouble"]))
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

    for op in ("$eq", "$ne", "$gt", "$gte", "$lt", "$lte", "$and", "$or"):
        if op in expr:
            return _eval_bool(doc, expr)
    return expr


def _eval_bool(doc: dict, expr) -> bool:
    """Evaluate a boolean aggregation expression."""
    if isinstance(expr, bool):
        return expr
    if not isinstance(expr, dict):
        return bool(_eval_expr(doc, expr))
    if "$and" in expr:
        return all(_eval_bool(doc, sub) for sub in expr["$and"])
    if "$or" in expr:
        return any(_eval_bool(doc, sub) for sub in expr["$or"])
    for op, cmp_fn in (
        ("$eq", lambda a, b: a == b),
        ("$ne", lambda a, b: a != b),
    ):
        if op in expr:
            a, b = (_eval_expr(doc, e) for e in expr[op])
            return cmp_fn(a, b)
    for op, cmp_fn in _CMP.items():
        if op in expr:
            a, b = (_eval_expr(doc, e) for e in expr[op])
            if a is None or b is None:
                return False
            try:
                return cmp_fn(a, b)
            except TypeError:
                return False
    return bool(_eval_expr(doc, expr))


def _run_project(docs: list, project_spec: dict) -> list:
    """Apply a $project stage, evaluating each field expression per document."""
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
            return None
        resolved = {}
        for k, v in id_spec.items():
            if isinstance(v, dict) and "$dateTrunc" in v:
                resolved[k] = None
            else:
                resolved[k] = _resolve_field(doc, v)
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
                bucket = grp.setdefault(acc_name, set())
                if val is not None:
                    bucket.add(val)
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
            elif op == "$min":
                cur = grp.get(acc_name)
                if val is not None and (cur is None or val < cur):
                    grp[acc_name] = val
                elif is_new:
                    grp[acc_name] = val
            elif op == "$max":
                cur = grp.get(acc_name)
                if val is not None and (cur is None or val > cur):
                    grp[acc_name] = val
                elif is_new:
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


def _run_pipeline(docs: list, pipeline: list) -> list:
    results = list(docs)
    for stage in pipeline:
        if "$match" in stage:
            results = _match_all(results, stage["$match"])
        elif "$sort" in stage:
            sort_spec = stage["$sort"]
            for field, direction in reversed(list(sort_spec.items())):
                results.sort(
                    key=lambda d, f=field: (d.get(f) is None, d.get(f)),
                    reverse=(direction == -1),
                )
        elif "$group" in stage:
            results = _run_group(results, stage["$group"])
        elif "$project" in stage:
            results = _run_project(results, stage["$project"])
        elif "$limit" in stage:
            results = results[: stage["$limit"]]
        elif "$unwind" in stage:
            field_expr = stage["$unwind"]
            field = field_expr.lstrip("$") if isinstance(field_expr, str) else field_expr
            unwound = []
            for d in results:
                values = d.get(field, [])
                if isinstance(values, list):
                    for v in values:
                        new_d = dict(d)
                        new_d[field] = v
                        unwound.append(new_d)
                elif values is not None:
                    unwound.append(d)
            results = unwound
        # $addFields, $facet, $lookup intentionally skipped.
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
    """Chainable cursor for ``find()``. Supports skip/limit/sort."""

    def __init__(self, docs: dict, query: dict, sort=None, limit: int = 0, skip: int = 0):
        self._docs = docs
        self._query = query
        self._sort: list[tuple[str, int]] = list(sort) if sort else []
        self._skip_n = skip
        self._limit_n = limit
        self._iter = None

    def skip(self, n: int) -> "_FakeCursor":
        self._skip_n = n
        return self

    def limit(self, n: int) -> "_FakeCursor":
        self._limit_n = n
        return self

    def sort(self, key_or_list, direction: int = 1) -> "_FakeCursor":
        if isinstance(key_or_list, list):
            self._sort = list(key_or_list)
        else:
            self._sort = [(key_or_list, direction)]
        return self

    def _filtered(self) -> list:
        results = [d for d in self._docs.values() if _match_doc(d, self._query)]
        for key, direction in reversed(self._sort):
            results.sort(
                key=lambda d, k=key: (d.get(k) is None, d.get(k)),
                reverse=direction < 0,
            )
        results = results[self._skip_n :]
        if self._limit_n:
            results = results[: self._limit_n]
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


def _matched_key(docs: dict, query: dict) -> Any:
    """Return the key of the first doc matching ``query`` (full operator support)."""
    for key, doc in docs.items():
        if _match_doc(doc, query):
            return key
    return None


class FakeCollection:
    """In-process collection covering the Motor API surface that the app uses."""

    def __init__(self):
        self._docs: dict = {}

    # -- writes -----------------------------------------------------------

    async def insert_one(self, doc: dict):
        key = doc.get("_id") or str(len(self._docs))
        self._docs[key] = dict(doc)
        result = MagicMock()
        result.inserted_id = key
        return result

    async def insert_many(self, docs: list, ordered: bool = True):
        inserted = []
        for doc in docs:
            key = doc.get("_id") or str(len(self._docs))
            self._docs[key] = dict(doc)
            inserted.append(key)
        result = MagicMock()
        result.inserted_ids = inserted
        return result

    async def update_one(self, query, update, upsert: bool = False):
        matched = _matched_key(self._docs, query)
        modified = 0
        if matched is not None:
            self._apply_update(self._docs[matched], update)
            modified = 1
        elif upsert:
            doc: dict = {}
            for k, v in query.items():
                if not isinstance(v, dict) and not k.startswith("$"):
                    doc[k] = v
            on_insert = update.get(_SET_ON_INSERT, {})
            doc.update(on_insert)
            self._apply_update(doc, update, skip_set_on_insert=True)
            key = doc.get("_id") or str(len(self._docs))
            doc["_id"] = key
            self._docs[key] = doc
        result = MagicMock()
        result.modified_count = modified
        return result

    async def update_many(self, query, update, array_filters=None, upsert: bool = False):
        matched = [k for k, doc in self._docs.items() if _match_doc(doc, query)]
        for k in matched:
            self._apply_update(self._docs[k], update)
        if not matched and upsert:
            doc = {k: v for k, v in query.items() if not isinstance(v, dict) and not k.startswith("$")}
            self._apply_update(doc, update, skip_set_on_insert=True)
            key = doc.get("_id") or str(len(self._docs))
            doc["_id"] = key
            self._docs[key] = doc
        result = MagicMock()
        result.modified_count = len(matched)
        result.matched_count = len(matched)
        return result

    def with_options(self, **_kwargs) -> "FakeCollection":
        # Read-preference / write-concern variations are no-ops in-process.
        return self

    async def find_one_and_update(
        self, query, update, return_document: bool = False, upsert: bool = False, **_kwargs
    ):
        matched = _matched_key(self._docs, query)
        if matched is None:
            if not upsert:
                return None
            doc = {k: v for k, v in query.items() if not isinstance(v, dict) and not k.startswith("$")}
            self._apply_update(doc, update, skip_set_on_insert=True)
            key = doc.get("_id") or str(len(self._docs))
            doc["_id"] = key
            self._docs[key] = doc
            return doc if return_document else None
        before = dict(self._docs[matched])
        self._apply_update(self._docs[matched], update)
        return self._docs[matched] if return_document else before

    @staticmethod
    def _apply_update(target: dict, update: dict, skip_set_on_insert: bool = False) -> None:
        for op, payload in update.items():
            if op == "$set":
                target.update(payload)
            elif op == "$setOnInsert" and not skip_set_on_insert:
                # only applied when called outside upsert insert path
                for k, v in payload.items():
                    target.setdefault(k, v)
            elif op == "$inc":
                for field, delta in payload.items():
                    target[field] = target.get(field, 0) + delta
            elif op == "$addToSet":
                for field, value in payload.items():
                    bucket = target.setdefault(field, [])
                    if value not in bucket:
                        bucket.append(value)

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
            matched = _matched_key(self._docs, flt)
            if matched is not None:
                self._apply_update(self._docs[matched], upd)
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
                self._docs[doc["_id"]] = doc
        result = MagicMock()
        result.modified_count = modified
        return result

    async def create_index(self, *args, **kwargs):
        return None

    # -- reads ------------------------------------------------------------

    async def find_one(self, query, projection=None):
        # Fast path for _id-only queries (common in repository code)
        if set(query.keys()) == {"_id"} and not isinstance(query["_id"], dict):
            return self._docs.get(query["_id"])
        for doc in self._docs.values():
            if _match_doc(doc, query):
                return doc
        return None

    async def count_documents(self, query):
        return sum(1 for doc in self._docs.values() if _match_doc(doc, query))

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
        cursor = _FakeCursor(
            self._docs,
            query or {},
            sort=kwargs.get("sort"),
            limit=kwargs.get("limit", 0),
            skip=kwargs.get("skip", 0),
        )
        return cursor

    def aggregate(self, pipeline: list, **_kwargs) -> _AsyncIter:
        # ``allowDiskUse`` (and any other server-side option) is a no-op in-process.
        return _AsyncIter(_run_pipeline(list(self._docs.values()), pipeline))


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
            object.__setattr__(self, name, FakeCollection())

    def __getattr__(self, name: str) -> FakeCollection:
        # Auto-vivify collections so repositories that touch unexpected ones
        # don't AttributeError before the test even runs.
        col = FakeCollection()
        object.__setattr__(self, name, col)
        return col

    def __getitem__(self, name: str) -> FakeCollection:
        return getattr(self, name)
