"""B5: ad-hoc analysis must leave no MongoDB document, no GridFS blob, no file and no caller-derived cache entry."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import pymongo
import pytest
import redis.asyncio
from motor import motor_asyncio

from app.core.cache import CacheKeys, CacheService, cache_service
from app.core.config import settings
from app.db import mongodb
from app.schemas.adhoc import AdhocAnalyzeRequest, AdhocAnalyzeResponse
from app.services.analysis.adhoc import run_adhoc_analysis
from app.services.analysis.registry import analyzers
from tests.mocks.fake_mongo import FakeCollection, FakeDatabase

# The scan-backed pipeline's collections plus the GridFS indexes. A floor, not a closed set:
# the runtime sweep below also covers whatever the run vivified that nobody listed here.
_PERSISTENCE_COLLECTIONS: tuple[str, ...] = (
    "scans",
    "findings",
    "dependencies",
    "analysis_results",
    "crypto_assets",
    "webhook_deliveries",
    "fs.files",
    "fs.chunks",
)

# Fail closed: a collection method outside this set counts as a write, so a driver call
# nobody anticipated is a violation until someone classifies it deliberately.
_COLLECTION_READS = frozenset(
    {
        "count_documents",
        "distinct",
        "estimated_document_count",
        "find",
        "find_one",
        "index_information",
        "list_indexes",
        "watch",
    }
)

_AGGREGATE = "aggregate"
# The one method whose read-ness depends on its argument: these stages write server-side.
_WRITING_AGGREGATION_STAGES = frozenset({"$out", "$merge"})

# Reaching a datastore other than through the injected handle: the module-level accessors,
# or a driver client/bucket built from scratch, which never touches those modules at all.
_BYPASS_ENTRY_POINTS = ("get_database", "connect_to_mongo", "primary_gridfs_bucket")

_MOTOR_CLIENT_LABEL = "motor.motor_asyncio.AsyncIOMotorClient"
_GRIDFS_BUCKET_LABEL = "motor.motor_asyncio.AsyncIOMotorGridFSBucket"
_PYMONGO_CLIENT_LABEL = "pymongo.MongoClient"
_PYMONGO_ASYNC_CLIENT_LABEL = "pymongo.AsyncMongoClient"
_REDIS_CLIENT_LABEL = "redis.asyncio.Redis"
_REDIS_FROM_URL_LABEL = "redis.asyncio.from_url"

# Captured at import, before any test rebinds them, so the fixture patches by original identity.
_DRIVER_ENTRY_POINTS: tuple[tuple[str, Any], ...] = (
    (_MOTOR_CLIENT_LABEL, motor_asyncio.AsyncIOMotorClient),
    (_GRIDFS_BUCKET_LABEL, motor_asyncio.AsyncIOMotorGridFSBucket),
    (_PYMONGO_CLIENT_LABEL, pymongo.MongoClient),
    (_PYMONGO_ASYNC_CLIENT_LABEL, pymongo.AsyncMongoClient),
    (_REDIS_CLIENT_LABEL, redis.asyncio.Redis),
    (_REDIS_FROM_URL_LABEL, redis.asyncio.from_url),
)

# Upstream reference lists shared by every caller: the key names the source, never the payload.
_UPSTREAM_REFERENCE_CACHE_KEYS = frozenset(
    {
        CacheKeys.popular_packages("npm"),
        CacheKeys.popular_packages("pypi"),
        CacheKeys.kev_catalog(),
    }
)

# The run reads the shared cache and publishes nothing back. An equality assertion on the
# reads, so an analyzer that stops running cannot quietly shrink the cache nets to nothing.
_EXPECTED_CACHE_READS = frozenset({CacheKeys.popular_packages("npm"), CacheKeys.popular_packages("pypi")})

_UPSTREAM_NPM_KEY = f"{settings.CACHE_PREFIX}{CacheKeys.popular_packages('npm')}"
_UNNAMED_COLLECTION = "a_collection_no_one_named"
_UNMODELLED_DRIVER_API = "get_collection"
_LEAK_ID = "leak"
_LEAK_SUFFIX = ".adhoc-leak"
_TEMP_ROOT_NAME = "adhoc-temp"
_CALLER_DERIVED_CACHE_KEY = "osv2:0123456789abcdef"
_SEEDED_POPULAR_PYPI = ["requests", "flask", "django"]
_MONGO_URL = "mongodb://localhost:27017"
_BASE_URL = "http://test"
_ANALYZE_PATH = "/api/v1/analyze"
_KEY_OWNER = "adhoc-user"
_KEY_NAME = "ci"
_KEY_DAYS = 30
_ANALYZE_ADHOC = "analyze:adhoc"
_FAILING_ANALYZER = "license_compliance"
_CACHING_ANALYZER = "typosquatting"
_ENRICHMENT = "epss_kev"
_REACHABILITY = "reachability"
# The SBOM below carries a cryptographic-asset component, so the crypto stage evaluates it.
_CRYPTO_RULES = "crypto_rules"

# A deliberately misspelled dependency. No upstream reference list can legitimately contain it,
# so finding it inside a shared cache value means caller data leaked in under a permitted key.
_CALLER_ONLY_COMPONENT = "expresss"

_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    "metadata": {"component": {"type": "application", "name": "demo-service", "version": "1.0.0"}},
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:pypi/requests@2.31.0",
            "name": "requests",
            "version": "2.31.0",
            "purl": "pkg:pypi/requests@2.31.0",
            "hashes": [{"alg": "SHA-256", "content": "a" * 64}],
            "licenses": [{"license": {"id": "AGPL-3.0-only"}}],
        },
        {
            "type": "library",
            "bom-ref": f"pkg:npm/{_CALLER_ONLY_COMPONENT}@4.18.2",
            "name": _CALLER_ONLY_COMPONENT,
            "version": "4.18.2",
            "purl": f"pkg:npm/{_CALLER_ONLY_COMPONENT}@4.18.2",
        },
        {
            "type": "cryptographic-asset",
            "bom-ref": "algo-sha1",
            "name": "SHA-1",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"primitive": "hash", "parameterSetIdentifier": "160"},
            },
        },
    ],
    "dependencies": [
        {"ref": "pkg:pypi/requests@2.31.0", "dependsOn": [f"pkg:npm/{_CALLER_ONLY_COMPONENT}@4.18.2"]},
        {"ref": f"pkg:npm/{_CALLER_ONLY_COMPONENT}@4.18.2", "dependsOn": []},
    ],
}

_TRUFFLEHOG = {
    "findings": [
        {
            "DetectorType": 8,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "app/config.py"}}},
        }
    ]
}

_OPENGREP = {
    "findings": [
        {
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "app/handlers.py",
            "start": {"line": 12},
            "end": {"line": 12},
            "extra": {"severity": "ERROR", "message": "eval() detected"},
        }
    ]
}

_BEARER = {
    "findings": [
        {
            "id": "python_lang_logger_leak",
            "title": "Sensitive data in logs",
            "filename": "app/audit.py",
            "line_number": 44,
            "severity": "high",
        }
    ]
}

_KICS = {
    "queries": [
        {
            "query_id": "8b25a4d0-1a17-4b1e-9ad9-9c2bd1e0a1d1",
            "query_name": "Container running as root",
            "severity": "HIGH",
            "files": [{"file_name": "deploy/pod.yaml", "line": 7}],
        }
    ]
}

# A callgraph the parsers actually read, so the reachability stage runs inside every net
# below; the scan-backed path bulk-writes its verdicts, and this one must not.
_CALLGRAPH = {
    "language": "python",
    "format": "generic",
    "analyzed_modules": ["requests"],
    "imports": [{"module": "requests", "file": "app/handlers.py", "line": 12, "symbols": ["get"]}],
}

_SCANNER_PAYLOADS = {"trufflehog": _TRUFFLEHOG, "opengrep": _OPENGREP, "bearer": _BEARER, "kics": _KICS}

# The two registered analyzers this path can carry to a verdict without a scan behind it:
# one pure, one cache-backed. The crypto analyzers read assets from a completed scan and the
# rest fan out to package registries, so both are resolved away before they can run.
_ANALYZERS = ["license_compliance", "typosquatting"]

# Every net below is only as wide as the run that exercises it, so the run's own reach is
# asserted by equality rather than by truthiness.
_EXPECTED_RAN = frozenset(_ANALYZERS) | frozenset(_SCANNER_PAYLOADS) | {_ENRICHMENT, _REACHABILITY, _CRYPTO_RULES}
_EXPECTED_SKIPPED = frozenset(analyzers) - frozenset(_ANALYZERS)


# ── Net 1: every call the run makes on a collection


class _WatchedCollection:
    """Delegates to a real FakeCollection, recording every call that is not a known read."""

    def __init__(self, name: str, inner: FakeCollection, writes: list[str]) -> None:
        self._name = name
        self._inner = inner
        self._writes = writes

    def with_options(self, **kwargs: Any) -> _WatchedCollection:
        # Returning the inner collection here would hand out an unwatched handle.
        self._inner.with_options(**kwargs)
        return self

    def __getattr__(self, attribute: str) -> Any:
        try:
            target = getattr(self._inner, attribute)
        except AttributeError:
            # A driver API the fake never modelled is exactly the unanticipated write this
            # net promises to catch. Dunders are Python's own probing, not a driver call.
            if not (attribute.startswith("__") and attribute.endswith("__")):
                self._writes.append(f"{self._name}.{attribute}")
            raise
        if attribute == _AGGREGATE:
            return self._watched_aggregate(target)
        if attribute in _COLLECTION_READS or not callable(target):
            return target

        def _record(*args: Any, **kwargs: Any) -> Any:
            self._writes.append(f"{self._name}.{attribute}")
            return target(*args, **kwargs)

        return _record

    def _watched_aggregate(self, target: Any) -> Any:
        def _aggregate(pipeline: Any, *args: Any, **kwargs: Any) -> Any:
            writing = sorted(
                stage_name
                for stage in (pipeline if isinstance(pipeline, list) else [])
                if isinstance(stage, dict)
                for stage_name in stage
                if stage_name in _WRITING_AGGREGATION_STAGES
            )
            if writing:
                self._writes.append(f"{self._name}.{_AGGREGATE}({','.join(writing)})")
            return target(pipeline, *args, **kwargs)

        return _aggregate

    def __call__(self, *_args: Any, **_kwargs: Any) -> Any:
        self._writes.append(f"{self._name}.__call__")
        raise TypeError(f"{self._name} is not callable")

    def __getitem__(self, key: str) -> Any:
        self._writes.append(f"{self._name}[{key}]")
        raise TypeError(f"{self._name} is not subscriptable")


class _WriteRecordingDatabase(FakeDatabase):
    """A FakeDatabase whose collections are all watched, pre-created and vivified alike."""

    def __init__(self) -> None:
        super().__init__()
        object.__setattr__(self, "writes", [])

    def __getattribute__(self, name: str) -> Any:
        value = object.__getattribute__(self, name)
        if isinstance(value, FakeCollection):
            return _WatchedCollection(name, value, object.__getattribute__(self, "writes"))
        return value

    def __getattr__(self, name: str) -> Any:
        return _WatchedCollection(name, super().__getattr__(name), self.writes)


def _collection_names(db: Any) -> list[str]:
    vivified = {name for name, value in vars(db).items() if isinstance(value, FakeCollection)}
    return sorted(vivified | set(_PERSISTENCE_COLLECTIONS))


async def assert_nothing_persisted(db: Any) -> None:
    for name in _collection_names(db):
        count = await db[name].count_documents({})
        assert count == 0, f"ad-hoc analysis wrote {count} document(s) into '{name}'"


async def collection_counts(db: Any) -> dict[str, int]:
    """A baseline for a handle that had to be seeded — with the caller's own key, say."""
    return {name: await db[name].count_documents({}) for name in _collection_names(db)}


async def assert_no_new_documents(db: Any, before: dict[str, int]) -> None:
    for name in _collection_names(db):
        count = await db[name].count_documents({})
        # A collection the run vivified is absent from the baseline, and a floor of zero is
        # what "the run must not create it" means.
        seeded = before.get(name, 0)
        assert count == seeded, f"ad-hoc analysis wrote {count - seeded} document(s) into '{name}'"


def assert_no_write_calls(db: _WriteRecordingDatabase) -> None:
    assert db.writes == [], f"ad-hoc analysis made write calls: {db.writes}"


# ── Net 2: a datastore reached without the injected handle


class _BypassTripwire:
    def __init__(self, label: str, touched: list[str]) -> None:
        self._label = label
        self._touched = touched

    def __call__(self, *_args: Any, **_kwargs: Any) -> Any:
        self._touched.append(self._label)
        raise AssertionError(f"ad-hoc analysis reached {self._label} instead of the injected handle")


class _TripwireClient:
    def __init__(self, touched: list[str]) -> None:
        self._touched = touched

    def __getitem__(self, name: str) -> Any:
        return self.__getattr__(f"[{name}]")

    def __getattr__(self, attribute: str) -> Any:
        self._touched.append(f"app.db.mongodb.db.client{attribute}")
        raise AssertionError("ad-hoc analysis reached the process-wide Mongo client")


def _rebind_everywhere(monkeypatch: pytest.MonkeyPatch, replacements: list[tuple[Any, Any]]) -> None:
    """Rebind by identity across sys.modules: a ``from x import y`` consumer holds its own reference."""
    for module in list(sys.modules.values()):
        if not isinstance(module, ModuleType):
            continue
        for attribute, value in list(vars(module).items()):
            for original, replacement in replacements:
                if value is original:
                    monkeypatch.setattr(module, attribute, replacement, raising=False)


@pytest.fixture
def bypass_attempts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    touched: list[str] = []
    replacements: list[tuple[Any, Any]] = [
        (getattr(mongodb, name), _BypassTripwire(f"app.db.mongodb.{name}", touched)) for name in _BYPASS_ENTRY_POINTS
    ]
    replacements += [(original, _BypassTripwire(label, touched)) for label, original in _DRIVER_ENTRY_POINTS]
    _rebind_everywhere(monkeypatch, replacements)
    monkeypatch.setattr(mongodb.db, "client", _TripwireClient(touched))
    return touched


# ── Nets 3 and 4: Redis key and value policy


class _RecordingRedis:
    """Minimal Redis stand-in that serves what it holds and records every key it touches."""

    def __init__(self, store: dict[str, str], writes: list[tuple[str, str]], reads: list[str]) -> None:
        self._store = store
        self._writes = writes
        self._reads = reads

    async def get(self, key: str) -> str | None:
        self._reads.append(key)
        return self._store.get(key)

    async def mget(self, keys: list[str]) -> list[str | None]:
        self._reads.extend(keys)
        return [self._store.get(key) for key in keys]

    async def exists(self, key: str) -> int:
        self._reads.append(key)
        return int(key in self._store)

    async def ping(self) -> bool:
        return True

    def pipeline(self) -> _RecordingPipeline:
        return _RecordingPipeline(self)

    def record(self, key: str, value: str | None = None) -> None:
        self._writes.append((key, value or ""))
        if value is not None:
            self._store[key] = value

    async def setex(self, key: str, _ttl: int, value: str) -> bool:
        self.record(key, value)
        return True

    async def set(self, key: str, value: str, **_kwargs: Any) -> bool:
        self.record(key, value)
        return True

    def __getattr__(self, attribute: str) -> Any:
        async def _record(*args: Any, **_kwargs: Any) -> Any:
            self.record(str(args[0]) if args else attribute)
            return None

        return _record


class _RecordingPipeline:
    def __init__(self, client: _RecordingRedis) -> None:
        self._client = client
        self._queued: list[tuple[str, str]] = []

    def setex(self, key: str, _ttl: int, value: str) -> None:
        self._queued.append((key, value))

    async def execute(self) -> list[bool]:
        for key, value in self._queued:
            self._client.record(key, value)
        self._queued = []
        return []


def _unprefixed(key: str) -> str:
    prefix = settings.CACHE_PREFIX
    return key[len(prefix) :] if key.startswith(prefix) else key


@dataclass(frozen=True)
class _RecordedCache:
    writes: list[tuple[str, str]]
    reads: list[str]

    def written_keys(self) -> set[str]:
        return {_unprefixed(key) for key, _ in self.writes}

    def read_keys(self) -> set[str]:
        return {_unprefixed(key) for key in self.reads}


def assert_no_caller_derived_cache_writes(writes: list[tuple[str, str]]) -> None:
    """Upstream reference data may be cached; anything keyed off the posted payload may not."""
    leaked = [key for key, _ in writes if _unprefixed(key) not in _UPSTREAM_REFERENCE_CACHE_KEYS]
    assert leaked == [], f"ad-hoc analysis cached caller-derived keys: {leaked}"


def assert_no_caller_data_in_shared_cache(writes: list[tuple[str, str]]) -> None:
    """A permitted key name is not a licence for its value: poisoning an upstream list still leaks."""
    poisoned = [key for key, value in writes if _CALLER_ONLY_COMPONENT in value]
    assert poisoned == [], f"ad-hoc analysis wrote caller data into shared cache keys: {poisoned}"


@pytest.fixture
def recording_cache(monkeypatch: pytest.MonkeyPatch) -> _RecordedCache:
    recorded = _RecordedCache([], [])
    seeded = {f"{settings.CACHE_PREFIX}{CacheKeys.popular_packages('pypi')}": json.dumps(_SEEDED_POPULAR_PYPI)}
    client = _RecordingRedis(seeded, recorded.writes, recorded.reads)

    async def _get_client(_self: CacheService) -> _RecordingRedis:
        return client

    async def _available(_self: CacheService) -> bool:
        return True

    monkeypatch.setattr(CacheService, "get_client", _get_client)
    monkeypatch.setattr(CacheService, "_ensure_available", _available)
    return recorded


# ── Net 5: the filesystem


class _FilesystemWatch:
    """Survivors under a private temp root and at the top of the working directory.

    Scoped that way so ordinary library temp usage cannot make the proof flaky: a scratch file
    the library removes leaves nothing, and bytecode caches deeper in the tree are out of view.
    """

    def __init__(self, temp_root: Path, working_directory: Path) -> None:
        self._temp_root = temp_root
        self._working_directory = working_directory
        self._entries_before = set(working_directory.iterdir())

    def leaked(self) -> list[str]:
        left_in_temp = [str(path) for path in self._temp_root.rglob("*") if path.is_file()]
        appeared_in_cwd = [str(path) for path in set(self._working_directory.iterdir()) - self._entries_before]
        return sorted(left_in_temp + appeared_in_cwd)


def assert_no_files_left_behind(watch: _FilesystemWatch) -> None:
    leaked = watch.leaked()
    assert leaked == [], f"ad-hoc analysis left files on disk: {leaked}"


@pytest.fixture
def filesystem_watch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> _FilesystemWatch:
    temp_root = tmp_path / _TEMP_ROOT_NAME
    temp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
    monkeypatch.setenv("TMPDIR", str(temp_root))
    return _FilesystemWatch(temp_root, Path.cwd())


# ── The proof


def _full_request() -> AdhocAnalyzeRequest:
    return AdhocAnalyzeRequest(
        sboms=[_SBOM],
        scanners=_SCANNER_PAYLOADS,
        analyzers=_ANALYZERS,
        callgraph=_CALLGRAPH,
        apply_global_waivers=True,
    )


async def _run_and_drain(request: AdhocAnalyzeRequest, db: Any) -> tuple[AdhocAnalyzeResponse, set[asyncio.Task[Any]]]:
    """Run to completion including anything handed to the loop, so a deferred write lands before the nets look."""
    before = asyncio.all_tasks()
    response = await run_adhoc_analysis(request, db)
    spawned = asyncio.all_tasks() - before - {asyncio.current_task()}
    await asyncio.gather(*spawned, return_exceptions=True)
    return response, spawned


@pytest.mark.asyncio
async def test_adhoc_analysis_persists_nothing(bypass_attempts, recording_cache, filesystem_watch):
    db = _WriteRecordingDatabase()

    response, spawned = await _run_and_drain(_full_request(), db)

    assert not spawned, f"ad-hoc analysis scheduled background work: {spawned}"
    assert_no_write_calls(db)
    await assert_nothing_persisted(db)
    assert bypass_attempts == []
    assert_no_caller_derived_cache_writes(recording_cache.writes)
    assert_no_caller_data_in_shared_cache(recording_cache.writes)
    assert_no_files_left_behind(filesystem_watch)

    # Reachability last: a leak is the more useful diagnosis when a mutant trips both.
    assert set(response.analyzers.ran) == set(_EXPECTED_RAN), "every net is only as wide as the run that reaches it"
    assert set(response.analyzers.skipped) == set(_EXPECTED_SKIPPED)
    assert set(response.analyzers.errored) == set()
    assert response.analyzers.skipped_inputs == {}
    assert response.findings, "the run must actually produce findings, or the proof is vacuous"
    assert recording_cache.read_keys() == set(_EXPECTED_CACHE_READS), (
        "the run must reach Redis exactly where it is expected to, or the cache nets are vacuous"
    )
    assert recording_cache.writes == []


@pytest.mark.asyncio
async def test_adhoc_analysis_persists_nothing_when_an_analyzer_fails(
    monkeypatch, bypass_attempts, recording_cache, filesystem_watch
):
    from app.services.analysis import registry

    class _Boom:
        name = _FAILING_ANALYZER

        async def analyze(self, sbom, settings=None, parsed_components=None):
            raise RuntimeError("upstream exploded")

    monkeypatch.setitem(registry.analyzers, _FAILING_ANALYZER, _Boom())

    db = _WriteRecordingDatabase()

    response, spawned = await _run_and_drain(_full_request(), db)

    assert not spawned, f"ad-hoc analysis scheduled background work: {spawned}"
    assert_no_write_calls(db)
    await assert_nothing_persisted(db)
    assert bypass_attempts == []
    assert_no_caller_derived_cache_writes(recording_cache.writes)
    assert_no_caller_data_in_shared_cache(recording_cache.writes)
    assert_no_files_left_behind(filesystem_watch)

    assert set(response.analyzers.errored) == {_FAILING_ANALYZER}, "the failure must reach the report"
    assert set(response.analyzers.ran) == set(_EXPECTED_RAN) - {_FAILING_ANALYZER}
    assert recording_cache.read_keys() == set(_EXPECTED_CACHE_READS)
    assert recording_cache.writes == []


@pytest.mark.asyncio
async def test_an_analyzer_that_caches_publishes_nothing_through_this_path(
    monkeypatch, bypass_attempts, recording_cache, filesystem_watch
):
    """The guarantee has to hold for any analyzer, not only for the ones the defaults allow."""
    from app.services.analysis import registry

    fetched: list[str] = []

    async def _fetch() -> list[str]:
        fetched.append(_CALLER_DERIVED_CACHE_KEY)
        return [_CALLER_ONLY_COMPONENT]

    class _Caching:
        name = _CACHING_ANALYZER

        async def analyze(self, sbom, settings=None, parsed_components=None):
            await cache_service.set(_CALLER_DERIVED_CACHE_KEY, [_CALLER_ONLY_COMPONENT])
            await cache_service.mset({_CALLER_DERIVED_CACHE_KEY: [_CALLER_ONLY_COMPONENT]})
            await cache_service.get_or_fetch_with_lock(_CALLER_DERIVED_CACHE_KEY, _fetch)
            await cache_service.delete(_UPSTREAM_NPM_KEY)
            return {"findings": []}

    monkeypatch.setitem(registry.analyzers, _CACHING_ANALYZER, _Caching())

    db = _WriteRecordingDatabase()

    response, spawned = await _run_and_drain(_full_request(), db)

    assert not spawned, f"ad-hoc analysis scheduled background work: {spawned}"
    assert_no_write_calls(db)
    assert bypass_attempts == []
    assert recording_cache.writes == []
    assert_no_files_left_behind(filesystem_watch)

    # The analyzer is silenced, not disabled: its upstream fetch still ran and it still contributed.
    assert fetched == [_CALLER_DERIVED_CACHE_KEY]
    assert _CACHING_ANALYZER in response.analyzers.ran


@pytest.fixture
def injected_database() -> Any:
    """Bound before the bypass tripwires replace the module attribute the app imported."""
    from app.db.mongodb import get_database
    from app.main import app

    database = _WriteRecordingDatabase()

    async def _use_it() -> _WriteRecordingDatabase:
        return database

    app.dependency_overrides[get_database] = _use_it
    yield database
    app.dependency_overrides.pop(get_database, None)


async def _seed_adhoc_key(db: Any) -> str:
    from app.repositories.adhoc_api_keys import AdhocApiKeyRepository

    _doc, plaintext = await AdhocApiKeyRepository(db).create(_KEY_OWNER, _KEY_NAME, _KEY_DAYS)
    await db.users.insert_one(
        {
            "_id": _KEY_OWNER,
            "username": _KEY_OWNER,
            "email": f"{_KEY_OWNER}@example.com",
            "permissions": [_ANALYZE_ADHOC],
            "is_active": True,
            "hashed_password": "x",
        }
    )
    return str(plaintext)


@pytest.mark.asyncio
async def test_the_endpoint_persists_nothing(injected_database, bypass_attempts, recording_cache, filesystem_watch):
    """Same guarantee one layer up: authentication resolves a key and stamps nothing on it."""
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    db = injected_database
    token = await _seed_adhoc_key(db)
    before = await collection_counts(db)
    # The key and its owner are the caller's credentials, not the run's output.
    db.writes.clear()

    request = _full_request()
    async with AsyncClient(transport=ASGITransport(app=app), base_url=_BASE_URL) as ac:
        resp = await ac.post(
            _ANALYZE_PATH,
            json=request.model_dump(exclude_none=True),
            headers={"Authorization": f"Bearer {token}"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["findings"], "the request must actually produce findings, or the proof is vacuous"
    assert set(body["analyzers"]["ran"]) == set(_EXPECTED_RAN)

    assert_no_write_calls(db)
    await assert_no_new_documents(db, before)
    assert bypass_attempts == []
    assert_no_caller_derived_cache_writes(recording_cache.writes)
    assert_no_caller_data_in_shared_cache(recording_cache.writes)
    assert_no_files_left_behind(filesystem_watch)
    assert recording_cache.writes == []


@pytest.mark.asyncio
async def test_cache_suppression_does_not_outlive_the_run(recording_cache):
    await run_adhoc_analysis(_full_request(), FakeDatabase())

    assert await cache_service.set(_CALLER_DERIVED_CACHE_KEY, [_LEAK_ID]) is True
    assert recording_cache.written_keys() == {_CALLER_DERIVED_CACHE_KEY}


# ── The proof's own detectors


@pytest.mark.asyncio
async def test_a_write_into_a_collection_no_one_named_is_caught():
    db = _WriteRecordingDatabase()

    await db[_UNNAMED_COLLECTION].insert_one({"_id": _LEAK_ID})

    assert db.writes == [f"{_UNNAMED_COLLECTION}.insert_one"]
    with pytest.raises(AssertionError, match=_UNNAMED_COLLECTION):
        await assert_nothing_persisted(db)


@pytest.mark.asyncio
async def test_a_document_added_after_the_baseline_is_caught():
    """The HTTP proof has to seed a key, so its net compares against a baseline rather than zero."""
    db = _WriteRecordingDatabase()
    await db.users.insert_one({"_id": _KEY_OWNER})
    before = await collection_counts(db)

    await assert_no_new_documents(db, before)

    await db.users.insert_one({"_id": _LEAK_ID})
    with pytest.raises(AssertionError, match="users"):
        await assert_no_new_documents(db, before)


@pytest.mark.asyncio
async def test_a_collection_the_baseline_never_saw_is_caught():
    db = _WriteRecordingDatabase()
    before = await collection_counts(db)

    await db[_UNNAMED_COLLECTION].insert_one({"_id": _LEAK_ID})

    with pytest.raises(AssertionError, match=_UNNAMED_COLLECTION):
        await assert_no_new_documents(db, before)


@pytest.mark.asyncio
async def test_a_write_that_leaves_no_document_behind_is_caught():
    db = _WriteRecordingDatabase()

    await db.scans.insert_one({"_id": _LEAK_ID})
    await db.scans.delete_one({"_id": _LEAK_ID})

    await assert_nothing_persisted(db)
    with pytest.raises(AssertionError, match="insert_one"):
        assert_no_write_calls(db)


def test_a_driver_api_the_fake_never_modelled_is_caught():
    db = _WriteRecordingDatabase()

    with pytest.raises(TypeError):
        db.get_collection(_UNNAMED_COLLECTION)
    with pytest.raises(TypeError):
        db.client[_UNNAMED_COLLECTION]
    with pytest.raises(AttributeError):
        db.scans.audit  # noqa: B018

    assert db.writes == [f"{_UNMODELLED_DRIVER_API}.__call__", f"client[{_UNNAMED_COLLECTION}]", "scans.audit"]


@pytest.mark.asyncio
async def test_an_aggregation_stage_that_writes_server_side_is_caught():
    db = _WriteRecordingDatabase()

    await db.findings.aggregate([{"$match": {}}]).to_list(None)
    assert_no_write_calls(db)

    await db.findings.aggregate([{"$match": {}}, {"$merge": {"into": _UNNAMED_COLLECTION}}]).to_list(None)

    with pytest.raises(AssertionError, match=r"\$merge"):
        assert_no_write_calls(db)


@pytest.mark.asyncio
async def test_work_deferred_to_the_event_loop_is_caught(monkeypatch):
    db = _WriteRecordingDatabase()

    async def _leaky(_request: AdhocAnalyzeRequest, database: Any) -> AdhocAnalyzeResponse:
        async def _later() -> None:
            await asyncio.sleep(0)
            await database[_UNNAMED_COLLECTION].insert_one({"_id": _LEAK_ID})

        asyncio.get_running_loop().create_task(_later())
        return AdhocAnalyzeResponse()

    monkeypatch.setattr(sys.modules[__name__], "run_adhoc_analysis", _leaky)

    _response, spawned = await _run_and_drain(_full_request(), db)

    assert spawned, "a task handed to the loop must be visible before the nets are asserted"
    assert db.writes == [f"{_UNNAMED_COLLECTION}.insert_one"]


def test_reaching_mongo_without_the_injected_handle_is_caught(bypass_attempts):
    from app.api import deps

    with pytest.raises(AssertionError):
        deps.get_database()

    assert bypass_attempts == ["app.db.mongodb.get_database"]


@pytest.mark.parametrize(
    ("label", "construct"),
    [
        (_MOTOR_CLIENT_LABEL, lambda: motor_asyncio.AsyncIOMotorClient(_MONGO_URL)),
        (_GRIDFS_BUCKET_LABEL, lambda: motor_asyncio.AsyncIOMotorGridFSBucket(FakeDatabase())),
        (_PYMONGO_CLIENT_LABEL, lambda: pymongo.MongoClient(_MONGO_URL)),
        (_PYMONGO_ASYNC_CLIENT_LABEL, lambda: pymongo.AsyncMongoClient(_MONGO_URL)),
        (_REDIS_CLIENT_LABEL, lambda: redis.asyncio.Redis()),
        (_REDIS_FROM_URL_LABEL, lambda: redis.asyncio.from_url(settings.REDIS_URL)),
    ],
)
def test_a_directly_constructed_driver_client_is_caught(bypass_attempts, label, construct):
    with pytest.raises(AssertionError):
        construct()

    assert bypass_attempts == [label]


def test_a_caller_derived_cache_key_is_caught():
    assert_no_caller_derived_cache_writes([(_UPSTREAM_NPM_KEY, "")])

    with pytest.raises(AssertionError, match=_CALLER_DERIVED_CACHE_KEY):
        assert_no_caller_derived_cache_writes([(f"{settings.CACHE_PREFIX}{_CALLER_DERIVED_CACHE_KEY}", "")])


def test_caller_data_cached_under_a_permitted_upstream_key_is_caught():
    assert_no_caller_data_in_shared_cache([(_UPSTREAM_NPM_KEY, json.dumps(_SEEDED_POPULAR_PYPI))])

    with pytest.raises(AssertionError, match=_UPSTREAM_NPM_KEY):
        assert_no_caller_data_in_shared_cache([(_UPSTREAM_NPM_KEY, json.dumps([_CALLER_ONLY_COMPONENT]))])


def test_a_file_left_behind_is_caught(filesystem_watch):
    with tempfile.NamedTemporaryFile("w", suffix=_LEAK_SUFFIX, delete=False) as handle:
        handle.write(_LEAK_ID)

    with pytest.raises(AssertionError, match=_LEAK_SUFFIX):
        assert_no_files_left_behind(filesystem_watch)


def test_a_temp_file_the_library_cleans_up_is_not_a_leak(filesystem_watch):
    with tempfile.NamedTemporaryFile("w", suffix=_LEAK_SUFFIX) as handle:
        handle.write(_LEAK_ID)

    assert_no_files_left_behind(filesystem_watch)
