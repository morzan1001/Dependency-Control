"""
Fixtures for integration tests.

These tests exercise endpoint behaviour end-to-end via ``httpx.AsyncClient``
against the real FastAPI app, but with the MongoDB and auth dependencies
replaced by lightweight in-process mocks so that no live database or API key
infrastructure is required.
"""

import asyncio
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from fastapi import Depends
from httpx import AsyncClient, ASGITransport

from app.models.project import Project

_SET_ON_INSERT = "$setOnInsert"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _match_range_ops(value, ops_dict: dict) -> bool:
    """Evaluate Mongo $gte/$lte/$gt/$lt operators against ``value``.

    Consolidates what used to be two independent implementations (one here,
    one on _FakeCollection) so every fake-DB matcher agrees. If a range op
    is present but ``value`` is None the doc does not match — mirroring
    MongoDB's behaviour with missing fields.
    """
    import operator as _op

    _CMP = {"$lt": _op.lt, "$lte": _op.le, "$gt": _op.gt, "$gte": _op.ge}
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


def _fake_match_doc(doc: dict, query: dict) -> bool:
    """Return True if doc matches a simple MongoDB query (field equality + $in + $regex + range ops)."""
    for key, condition in query.items():
        value = doc.get(key)
        if isinstance(condition, dict):
            if "$in" in condition:
                if value not in condition["$in"]:
                    return False
            if "$regex" in condition:
                import re

                flags = re.IGNORECASE if condition.get("$options") == "i" else 0
                if not re.search(condition["$regex"], str(value or ""), flags):
                    return False
            if not _match_range_ops(value, condition):
                return False
        else:
            if value != condition:
                return False
    return True


def _fake_match(docs: list, query: dict) -> list:
    return [d for d in docs if _fake_match_doc(d, query)]


def _resolve_field(doc: dict, expr):
    """Resolve a field reference like '$field' or a plain value."""
    if isinstance(expr, str) and expr.startswith("$"):
        return doc.get(expr[1:])
    return expr


def _resolve_group_key(doc: dict, id_spec) -> object:
    """Resolve the _id expression in a $group stage to a hashable key."""
    if id_spec is None:
        return None
    if isinstance(id_spec, str) and id_spec.startswith("$"):
        val = doc.get(id_spec[1:])
        # $dateTrunc expressions are dicts; we map them to None so bucket grouping
        # produces a single bucket (empty results) rather than raising an error.
        return val
    if isinstance(id_spec, dict):
        # Check for $dateTrunc — return None to avoid errors
        if "$dateTrunc" in id_spec:
            return None
        result = {}
        for k, v in id_spec.items():
            if isinstance(v, dict) and "$dateTrunc" in v:
                result[k] = None
            else:
                result[k] = _resolve_field(doc, v)
        try:
            return tuple(sorted(result.items()))
        except TypeError:
            return str(result)
    return id_spec


def _fake_group(docs: list, group_spec: dict) -> list:
    """Minimal $group implementation covering $sum, $first, $addToSet, $push, $min, $max."""
    id_expr = group_spec.get("_id")
    accumulators = {k: v for k, v in group_spec.items() if k != "_id"}

    groups: dict = {}  # key -> accumulated state
    key_order: list = []

    for doc in docs:
        key = _resolve_group_key(doc, id_expr)
        hashable = key if not isinstance(key, dict) else str(key)
        if hashable not in groups:
            groups[hashable] = {"_id_val": key}
            key_order.append(hashable)
            for acc_name, acc_expr in accumulators.items():
                op = list(acc_expr.keys())[0]
                if op == "$sum":
                    val = acc_expr["$sum"]
                    # Literal numeric $sum (e.g. {$sum: 1}): resolve on first doc
                    # so the first document contributes its value immediately.
                    if isinstance(val, (int, float)):
                        groups[hashable][acc_name] = val
                    else:
                        groups[hashable][acc_name] = _resolve_field(doc, val) or 0
                elif op == "$first":
                    groups[hashable][acc_name] = _resolve_field(doc, acc_expr["$first"])
                elif op in ("$addToSet",):
                    groups[hashable][acc_name] = set()
                elif op == "$push":
                    groups[hashable][acc_name] = []
                elif op in ("$min", "$max"):
                    groups[hashable][acc_name] = _resolve_field(doc, acc_expr[op])
        else:
            for acc_name, acc_expr in accumulators.items():
                op = list(acc_expr.keys())[0]
                field_val = _resolve_field(doc, acc_expr[op])
                cur = groups[hashable][acc_name]
                if op == "$sum":
                    increment = field_val if isinstance(field_val, (int, float)) else 1
                    groups[hashable][acc_name] = cur + increment
                elif op == "$first":
                    pass  # keep first value
                elif op == "$addToSet":
                    if field_val is not None:
                        cur.add(field_val)
                elif op == "$push":
                    cur.append(field_val)
                elif op == "$min":
                    if field_val is not None and (cur is None or field_val < cur):
                        groups[hashable][acc_name] = field_val
                elif op == "$max":
                    if field_val is not None and (cur is None or field_val > cur):
                        groups[hashable][acc_name] = field_val

    result = []
    for hashable in key_order:
        state = groups[hashable]
        row = {"_id": state.pop("_id_val")}
        for k, v in state.items():
            row[k] = list(v) if isinstance(v, set) else v
        result.append(row)
    return result


def _make_project(project_id: str = "test-project-id", name: str = "test-project") -> Project:
    return Project(id=project_id, name=name)


class _FakeCursor:
    """Chainable cursor returned by _FakeCollection.find()."""

    def __init__(self, docs: dict, query: dict):
        self._docs = docs
        self._query = query
        self._skip_n = 0
        self._limit_n = 0
        self._sort_key: str | None = None
        self._sort_dir: int = 1  # 1 = ASC, -1 = DESC

    def skip(self, n: int) -> "_FakeCursor":
        self._skip_n = n
        return self

    def limit(self, n: int) -> "_FakeCursor":
        self._limit_n = n
        return self

    def sort(self, key: str, direction: int = 1) -> "_FakeCursor":
        self._sort_key = key
        self._sort_dir = direction
        return self

    def _matches(self, doc: dict) -> bool:
        for k, v in self._query.items():
            if isinstance(v, dict):
                val = doc.get(k)
                if "$regex" in v:
                    import re

                    flags = re.IGNORECASE if v.get("$options") == "i" else 0
                    if not re.search(v["$regex"], str(val or ""), flags):
                        return False
                if "$in" in v and val not in v["$in"]:
                    return False
                if not _match_range_ops(val, v):
                    return False
            elif doc.get(k) != v:
                return False
        return True

    async def to_list(self, length=None) -> list:
        results = [d for d in self._docs.values() if self._matches(d)]
        if self._sort_key is not None:
            results.sort(
                key=lambda d: (d.get(self._sort_key) is None, d.get(self._sort_key)),
                reverse=(self._sort_dir == -1),
            )
        results = results[self._skip_n :]
        if self._limit_n:
            results = results[: self._limit_n]
        return results


class _FakeCollection:
    """Minimal in-process collection that supports the operations used by the
    CBOM ingest endpoint and the CryptoAssetRepository."""

    def __init__(self):
        self._docs: dict = {}

    async def update_one(self, query, update, upsert=False):
        # Find existing doc matching the query by any fields
        matched_key = None
        for k, doc in self._docs.items():
            if all(doc.get(fk) == fv for fk, fv in query.items()):
                matched_key = k
                break

        if matched_key is not None:
            set_ops = update.get("$set", {})
            self._docs[matched_key].update(set_ops)
        elif upsert:
            doc = dict(query)
            on_insert = update.get(_SET_ON_INSERT, {})
            doc.update(on_insert)
            set_ops = update.get("$set", {})
            doc.update(set_ops)
            key = doc.get("_id") or str(len(self._docs))
            self._docs[key] = doc
        result = MagicMock()
        result.modified_count = 1
        return result

    async def find_one(self, query):
        key = query.get("_id") or query.get("_id")
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
            if self._doc_matches_query(doc, query):
                count += 1
        return count

    async def bulk_write(self, ops, ordered=True):
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
            elif upsert:
                on_insert = upd.get(_SET_ON_INSERT, {})
                set_ops = upd.get("$set", {})
                doc = {}
                # On upsert, setOnInsert provides the initial values (includes _id from model)
                doc.update(on_insert)
                # Then $set applies (model_dump with exclude={"id"} means _id is not here)
                doc.update(set_ops)
                # The key should be the _id (either from on_insert or generated)
                # Since model_dump(exclude={"id"}) removes _id, but the model itself has an id
                # We need to extract it from somewhere. In real MongoDB, bulk_upsert would
                # include _id in $setOnInsert. For testing, we'll reconstruct from filter.
                if "_id" not in doc:
                    # Fallback: try to find _id in set_ops or generate from unique index
                    if "_id" in set_ops:
                        doc["_id"] = set_ops["_id"]
                    else:
                        # For crypto assets, create a unique key from project:scan:bom_ref
                        # This matches the unique index in the repository
                        doc["_id"] = f"{flt.get('project_id')}:{flt.get('scan_id')}:{flt.get('bom_ref')}"
                key = doc.get("_id", str(len(self._docs)))
                self._docs[key] = doc
        result = MagicMock()
        result.modified_count = len(ops)
        return result

    def _doc_matches_query(self, doc: dict, query: dict) -> bool:
        for fk, fv in query.items():
            val = doc.get(fk)
            if isinstance(fv, dict):
                if "$in" in fv and val not in fv["$in"]:
                    return False
                if not _match_range_ops(val, fv):
                    return False
            elif val != fv:
                return False
        return True

    async def delete_one(self, query):
        await asyncio.sleep(0)  # yield to event loop — keeps this a true coroutine
        matched_key = None
        for k, doc in self._docs.items():
            if all(doc.get(fk) == fv for fk, fv in query.items()):
                matched_key = k
                break
        if matched_key is not None:
            del self._docs[matched_key]
        result = MagicMock()
        result.deleted_count = 1 if matched_key is not None else 0
        return result

    async def delete_many(self, query):
        await asyncio.sleep(0)  # yield to event loop — keeps this a true coroutine
        keys_to_delete = [k for k, doc in self._docs.items() if self._doc_matches_query(doc, query)]
        for k in keys_to_delete:
            del self._docs[k]
        result = MagicMock()
        result.deleted_count = len(keys_to_delete)
        return result

    async def insert_one(self, doc: dict):
        key = doc.get("_id") or str(len(self._docs))
        self._docs[key] = dict(doc)
        result = MagicMock()
        result.inserted_id = key
        return result

    async def create_index(self, *args, **kwargs):
        return None

    async def distinct(self, field: str, filter: dict = None):
        filter = filter or {}
        values = []
        for doc in self._docs.values():
            if all(doc.get(k) == v for k, v in filter.items()):
                val = doc.get(field)
                if val not in values:
                    values.append(val)
        return values

    def find(self, query=None, projection=None):
        """Return a chainable cursor over matching documents.

        The ``projection`` argument is accepted for API compatibility with Motor
        but is not applied — the fake cursor returns full documents.
        """
        return _FakeCursor(self._docs, query or {})

    def aggregate(self, pipeline):
        """In-process aggregate supporting the pipeline shapes used by analytics services.

        Handles: $match (including $in, $regex), $sort, $group (with $sum, $first,
        $addToSet, $push, $min, $max), $limit, $unwind.

        Deliberately ignores $dateTrunc (returns None bucket key) so that trend
        endpoints return an empty but valid points list rather than erroring.
        """
        docs = list(self._docs.values())

        for stage in pipeline:
            if "$match" in stage:
                docs = _fake_match(docs, stage["$match"])
            elif "$sort" in stage:
                sort_spec = stage["$sort"]
                for field, direction in reversed(list(sort_spec.items())):
                    docs = sorted(
                        docs,
                        key=lambda d, f=field: (d.get(f) is None, d.get(f)),
                        reverse=(direction == -1),
                    )
            elif "$group" in stage:
                docs = _fake_group(docs, stage["$group"])
            elif "$limit" in stage:
                docs = docs[: stage["$limit"]]
            elif "$unwind" in stage:
                field_path = stage["$unwind"]
                if isinstance(field_path, str):
                    field_path = field_path.lstrip("$")
                unwound = []
                for doc in docs:
                    val = doc.get(field_path)
                    if isinstance(val, list):
                        for item in val:
                            new_doc = dict(doc)
                            new_doc[field_path] = item
                            unwound.append(new_doc)
                    elif val is not None:
                        unwound.append(doc)
                docs = unwound

        rows = docs

        class _AggCursor:
            def __init__(self, items):
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

        return _AggCursor(rows)


class _FakeDb:
    """Minimal in-process database exposing only the collections needed by the
    CBOM ingest path and project access checks."""

    def __init__(self):
        self.scans = _FakeCollection()
        self.crypto_assets = _FakeCollection()
        self.projects = _FakeCollection()
        self.dependencies = _FakeCollection()
        self.system_settings = _FakeCollection()
        self.teams = _FakeCollection()
        self.users = _FakeCollection()

    def __getattr__(self, name):
        # Return a fresh collection for any collection the dep chain happens to
        # touch (e.g. `users`, `gitlab_instances`, `github_instances`) so that
        # repository constructors don't AttributeError before auth logic fires.
        col = _FakeCollection()
        object.__setattr__(self, name, col)
        return col

    def __getitem__(self, name):
        return getattr(self, name)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def _project():
    return _make_project()


@pytest_asyncio.fixture
async def db():
    """In-process fake database shared across a single test."""
    return _FakeDb()


@pytest_asyncio.fixture
async def client(db, _project):
    """AsyncClient wired to the real FastAPI app with auth and DB overridden."""
    from app.main import app
    from app.api.deps import (
        get_project_for_ingest,
        get_database,
        get_current_user,
        get_current_active_user,
    )
    from app.models.user import User

    async def _fake_project_for_ingest():
        return _project

    async def _fake_get_database():
        return db

    from app.api.deps import oauth2_scheme

    async def _fake_get_current_user(token: str = Depends(oauth2_scheme)) -> User:
        """Parse JWT token and return user. Used by member auth tests."""
        try:
            from jose import jwt
            from app.core.config import settings

            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            username = payload.get("sub")
            permissions = payload.get("permissions", [])

            if not username:
                from fastapi import HTTPException

                raise HTTPException(status_code=401, detail="Invalid token")

            # Create a user object matching the token
            user = User(
                id=username,
                username=username,
                email=f"{username}@test.com",
                permissions=permissions,
                is_active=True,
            )
            return user
        except Exception as e:
            from fastapi import HTTPException

            raise HTTPException(status_code=401, detail=str(e)) from e

    async def _fake_get_current_active_user(current_user: User = Depends(_fake_get_current_user)) -> User:
        """Just return the user from get_current_user."""
        if not current_user.is_active:
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail="Inactive user")
        return current_user

    app.dependency_overrides[get_project_for_ingest] = _fake_project_for_ingest
    app.dependency_overrides[get_database] = _fake_get_database
    app.dependency_overrides[get_current_user] = _fake_get_current_user
    app.dependency_overrides[get_current_active_user] = _fake_get_current_active_user

    # Pre-populate the project so tests can look it up
    # Store the full project document with all fields
    project_doc = _project.model_dump(by_alias=True)
    await db.projects.update_one(
        {"_id": str(_project.id)},
        {_SET_ON_INSERT: project_doc},
        upsert=True,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    # Clean up overrides after each test
    app.dependency_overrides.pop(get_project_for_ingest, None)
    app.dependency_overrides.pop(get_database, None)
    app.dependency_overrides.pop(get_current_user, None)
    app.dependency_overrides.pop(get_current_active_user, None)


@pytest.fixture
def api_key_headers():
    """Dummy API key header value — auth is bypassed via dep override."""
    return {"X-API-Key": "test-project-id.dummy-secret"}


@pytest.fixture
def member_auth_headers(_project):
    """Create auth headers for a user who is a project member."""
    from app.models.user import User
    from app.models.project import ProjectMember
    from app.core.permissions import Permissions
    from jose import jwt
    from app.core.config import settings

    # Create a user that is a member of the test project
    user = User(
        id="test-user-1",
        username="testuser",
        email="test@example.com",
        permissions=[Permissions.PROJECT_READ, Permissions.PROJECT_CREATE],
        is_active=True,
    )

    # Add the user as a project member
    member = ProjectMember(user_id=str(user.id), role="viewer")
    if not _project.members:
        _project.members = []
    _project.members.append(member)

    # Create JWT token
    payload = {
        "sub": user.username,
        "permissions": user.permissions,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def regular_user_no_access():
    """Create a user who is NOT a project member."""
    from app.models.user import User
    from app.core.permissions import PRESET_USER

    return User(
        id="test-user-no-access",
        username="noaccess",
        email="noaccess@example.com",
        permissions=list(PRESET_USER),
        is_active=True,
    )


@pytest.fixture
def admin_auth_headers():
    """Create auth headers for a system admin (has system:manage permission)."""
    from app.core.permissions import PRESET_ADMIN
    from jose import jwt
    from app.core.config import settings

    payload = {
        "sub": "admin-user",
        "permissions": list(PRESET_ADMIN),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def owner_auth_headers_proj(client, db):
    """Auth headers for a user who owns project 'p' (project-level admin role).

    The username doubles as the user id because _fake_get_current_user sets id=username.
    """
    from app.models.project import ProjectMember, Project
    from app.core.permissions import PRESET_USER, Permissions
    from jose import jwt
    from app.core.config import settings

    # username == id because _fake_get_current_user decodes sub -> id=username
    username = "ownerp"
    permissions = list(PRESET_USER) + [Permissions.PROJECT_READ]

    # Create project "p" with this user as project-admin member
    project_p = Project(id="p", name="project-p")
    member = ProjectMember(user_id=username, role="admin")
    project_p.members = [member]

    project_doc = project_p.model_dump(by_alias=True)
    await db.projects.update_one(
        {"_id": "p"},
        {_SET_ON_INSERT: project_doc},
        upsert=True,
    )

    payload = {
        "sub": username,
        "permissions": permissions,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def owner_auth_headers_proj_p2(client, db):
    """Auth headers for a user who owns project 'p2' (project-level admin role)."""
    from app.models.project import ProjectMember, Project
    from app.core.permissions import PRESET_USER, Permissions
    from jose import jwt
    from app.core.config import settings

    username = "ownerp2"
    permissions = list(PRESET_USER) + [Permissions.PROJECT_READ]

    # Create project "p2" with this user as project-admin member
    project_p2 = Project(id="p2", name="project-p2")
    member = ProjectMember(user_id=username, role="admin")
    project_p2.members = [member]

    project_doc = project_p2.model_dump(by_alias=True)
    await db.projects.update_one(
        {"_id": "p2"},
        {_SET_ON_INSERT: project_doc},
        upsert=True,
    )

    payload = {
        "sub": username,
        "permissions": permissions,
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return {"Authorization": f"Bearer {token}"}
