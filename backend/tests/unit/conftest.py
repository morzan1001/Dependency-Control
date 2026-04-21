"""
Fixtures for unit tests.

Provides in-process fake database for testing repositories and services
without requiring MongoDB.
"""

import re as _re
from unittest.mock import MagicMock

import pytest_asyncio


_EXISTS = "$exists"
_REGEX = "$regex"


# ---------------------------------------------------------------------------
# Aggregate pipeline executor (supports the operators used by analytics)
# ---------------------------------------------------------------------------

def _match_doc(doc: dict, condition: dict) -> bool:
    """Return True if doc satisfies a $match condition."""
    for k, v in condition.items():
        if k.startswith("$"):
            continue
        field_val = doc.get(k)
        if isinstance(v, dict):
            if "$in" in v:
                if field_val not in v["$in"]:
                    return False
            elif "$regex" in v:
                flags = _re.IGNORECASE if v.get("$options") == "i" else 0
                if not _re.search(v["$regex"], str(field_val or ""), flags):
                    return False
            elif "$exists" in v:
                present = k in doc
                if bool(v["$exists"]) != present:
                    return False
            elif "$gte" in v or "$lte" in v or "$gt" in v or "$lt" in v:
                if "$gte" in v and not (field_val is not None and field_val >= v["$gte"]):
                    return False
                if "$lte" in v and not (field_val is not None and field_val <= v["$lte"]):
                    return False
                if "$gt" in v and not (field_val is not None and field_val > v["$gt"]):
                    return False
                if "$lt" in v and not (field_val is not None and field_val < v["$lt"]):
                    return False
            else:
                if field_val != v:
                    return False
        else:
            if field_val != v:
                return False
    return True


def _resolve_field(doc: dict, expr):
    """Resolve a field reference ($field) or nested expression from a doc."""
    if isinstance(expr, str) and expr.startswith("$"):
        # Support dotted paths like $a.b
        parts = expr[1:].split(".")
        val = doc
        for p in parts:
            if not isinstance(val, dict):
                return None
            val = val.get(p)
        return val
    if isinstance(expr, dict):
        if "$dateTrunc" in expr:
            # Fake: just return the raw date value (bucket rounding omitted)
            return _resolve_field(doc, expr["$dateTrunc"]["date"])
        if "$first" in expr:
            return _resolve_field(doc, expr["$first"])
    return expr


def _run_group(docs: list, stage: dict) -> list:
    """Execute a $group stage."""
    id_expr = stage["_id"]
    accumulators = {k: v for k, v in stage.items() if k != "_id"}
    groups: dict = {}

    for doc in docs:
        # Compute group key
        if id_expr is None:
            key = None
        elif isinstance(id_expr, str):
            key = _resolve_field(doc, id_expr)
        elif isinstance(id_expr, dict):
            # Could be a $dateTrunc expression or a dict of sub-fields
            if "$dateTrunc" in id_expr:
                key = _resolve_field(doc, id_expr)
            else:
                key = tuple(
                    (k, _resolve_field(doc, v)) for k, v in sorted(id_expr.items())
                )
        else:
            key = id_expr

        if key not in groups:
            groups[key] = {"_id": key}
            for acc_name, acc_expr in accumulators.items():
                op = list(acc_expr.keys())[0]
                if op == "$sum":
                    groups[key][acc_name] = 0
                elif op in ("$addToSet",):
                    groups[key][acc_name] = set()
                elif op in ("$push",):
                    groups[key][acc_name] = []
                elif op in ("$first",):
                    groups[key][acc_name] = None
                elif op in ("$min",):
                    groups[key][acc_name] = None
                elif op in ("$max",):
                    groups[key][acc_name] = None

        grp = groups[key]
        for acc_name, acc_expr in accumulators.items():
            op = list(acc_expr.keys())[0]
            field_expr = acc_expr[op]
            val = _resolve_field(doc, field_expr) if isinstance(field_expr, str) else field_expr

            if op == "$sum":
                if isinstance(val, (int, float)):
                    grp[acc_name] = grp[acc_name] + val
                else:
                    grp[acc_name] = grp[acc_name] + 1
            elif op == "$addToSet":
                if val is not None:
                    grp[acc_name].add(val)
            elif op == "$push":
                grp[acc_name].append(val)
            elif op == "$first":
                if grp[acc_name] is None:
                    grp[acc_name] = val
            elif op == "$min":
                if grp[acc_name] is None or (val is not None and val < grp[acc_name]):
                    grp[acc_name] = val
            elif op == "$max":
                if grp[acc_name] is None or (val is not None and val > grp[acc_name]):
                    grp[acc_name] = val

    # Convert sets to lists
    result = []
    for grp in groups.values():
        grp = dict(grp)
        for k, v in grp.items():
            if isinstance(v, set):
                grp[k] = list(v)
        # Convert tuple keys back to dicts
        if isinstance(grp["_id"], tuple):
            grp["_id"] = {k: v for k, v in grp["_id"]}
        result.append(grp)
    return result


def _run_pipeline(docs: list, pipeline: list) -> list:
    """Execute a simple aggregation pipeline over a list of dicts."""
    results = list(docs)
    for stage in pipeline:
        if "$match" in stage:
            results = [d for d in results if _match_doc(d, stage["$match"])]
        elif "$group" in stage:
            results = _run_group(results, stage["$group"])
        elif "$sort" in stage:
            sort_spec = stage["$sort"]
            for field, direction in reversed(list(sort_spec.items())):
                results.sort(
                    key=lambda d: (d.get(field) is None, d.get(field)),
                    reverse=(direction == -1),
                )
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
                else:
                    unwound.append(d)
            results = unwound
        # $project, $addFields, etc. are skipped (not needed by current tests)
    return results


class _FakeAggregateCursor:
    """Async-iterable cursor returned by _FakeCollection.aggregate()."""

    def __init__(self, results: list):
        self._results = results
        self._iter = None

    def __aiter__(self) -> "_FakeAggregateCursor":
        self._iter = iter(self._results)
        return self

    async def __anext__(self) -> dict:
        try:
            return next(self._iter)  # type: ignore[arg-type]
        except StopIteration:
            raise StopAsyncIteration


class _FakeCursor:
    """Chainable cursor returned by _FakeCollection.find()."""

    def __init__(self, docs: dict, query: dict):
        self._docs = docs
        self._query = query
        self._skip_n = 0
        self._limit_n = 0
        self._iter: list | None = None

    def skip(self, n: int) -> "_FakeCursor":
        self._skip_n = n
        return self

    def limit(self, n: int) -> "_FakeCursor":
        self._limit_n = n
        return self

    def _matches(self, doc: dict) -> bool:
        import re
        for k, v in self._query.items():
            if not isinstance(v, dict):
                if doc.get(k) != v:
                    return False
            elif _REGEX in v:
                flags = re.IGNORECASE if v.get("$options") == "i" else 0
                if not re.search(v[_REGEX], str(doc.get(k, "")), flags):
                    return False
            elif _EXISTS in v:
                field_present = k in doc
                if bool(v[_EXISTS]) != field_present:
                    return False
            elif doc.get(k) != v:
                return False
        return True

    def _filtered(self) -> list:
        results = [d for d in self._docs.values() if self._matches(d)]
        results = results[self._skip_n:]
        if self._limit_n:
            results = results[: self._limit_n]
        return results

    async def to_list(self, length=None) -> list:
        return self._filtered()

    def __aiter__(self) -> "_FakeCursor":
        self._iter = iter(self._filtered())
        return self

    async def __anext__(self) -> dict:
        try:
            return next(self._iter)  # type: ignore[arg-type]
        except StopIteration:
            raise StopAsyncIteration


class _FakeCollection:
    """Minimal in-process collection that supports the operations used by
    repositories."""

    def __init__(self):
        self._docs: dict = {}

    async def update_one(self, query, update, upsert=False):
        # Try to find an existing document matching the query
        matched_key = None
        for key, doc in self._docs.items():
            if all(doc.get(k) == v for k, v in query.items()):
                matched_key = key
                break

        if matched_key:
            # Update existing document
            set_ops = update.get("$set", {})
            self._docs[matched_key].update(set_ops)
        elif upsert:
            # Insert new document
            set_ops = update.get("$set", {})
            on_insert = update.get("$setOnInsert", {})
            doc = {}
            doc.update(set_ops)
            doc.update(on_insert)
            # Use _id if present, otherwise generate a key
            key = doc.get("_id") or query.get("_id") or str(len(self._docs))
            self._docs[key] = doc

        result = MagicMock()
        result.modified_count = 1
        return result

    async def insert_one(self, doc: dict):
        key = doc.get("_id", str(len(self._docs)))
        self._docs[key] = dict(doc)
        result = MagicMock()
        result.inserted_id = key
        return result

    async def find_one(self, query, projection=None):
        # search by _id
        key = query.get("_id")
        if key:
            return self._docs.get(key)
        # search by field
        for doc in self._docs.values():
            if all(doc.get(k) == v for k, v in query.items()):
                return doc
        return None

    async def count_documents(self, query):
        count = 0
        for doc in self._docs.values():
            if all(doc.get(k) == v for k, v in query.items()):
                count += 1
        return count

    async def bulk_write(self, ops, ordered=True):
        modified = 0
        for op in ops:
            # Each op is a pymongo UpdateOne
            flt = op._filter
            upd = op._doc
            upsert = op._upsert

            matched = [k for k, d in self._docs.items() if all(d.get(fk) == fv for fk, fv in flt.items())]
            if matched:
                key = matched[0]
                set_ops = upd.get("$set", {})
                self._docs[key].update(set_ops)
                modified += 1
            elif upsert:
                on_insert = upd.get("$setOnInsert", {})
                set_ops = upd.get("$set", {})
                doc = {}
                doc.update(set_ops)
                doc.update(on_insert)
                key = doc.get("_id") or flt.get("bom_ref", str(len(self._docs)))
                self._docs[key] = doc
        result = MagicMock()
        result.modified_count = modified
        return result

    async def create_index(self, *args, **kwargs):
        return None

    def find(self, query=None, projection=None, **kwargs):
        """Return a chainable cursor over matching documents."""
        return _FakeCursor(self._docs, query or {})

    def aggregate(self, pipeline: list) -> "_FakeAggregateCursor":
        """Execute a simplified aggregation pipeline in-process."""
        docs = list(self._docs.values())
        results = _run_pipeline(docs, pipeline)
        return _FakeAggregateCursor(results)

    async def delete_one(self, query):
        key = query.get("_id")
        if key and key in self._docs:
            del self._docs[key]
        result = MagicMock()
        result.deleted_count = 1
        return result


class _FakeDb:
    """Minimal in-process database exposing collections needed by repositories."""

    def __init__(self):
        self.crypto_policies = _FakeCollection()
        self.crypto_assets = _FakeCollection()
        self.projects = _FakeCollection()
        self.dependencies = _FakeCollection()
        self.system_settings = _FakeCollection()
        self.scans = _FakeCollection()
        self.findings = _FakeCollection()

    def __getattr__(self, name):
        # Return a fresh collection for any collection the dep chain happens to
        # touch so that repository constructors don't AttributeError.
        col = _FakeCollection()
        object.__setattr__(self, name, col)
        return col

    def __getitem__(self, name):
        return getattr(self, name)


@pytest_asyncio.fixture
async def db():
    """In-process fake database for unit tests."""
    return _FakeDb()
