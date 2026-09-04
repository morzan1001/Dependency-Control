"""B5: ad-hoc analysis must leave no MongoDB document, no GridFS blob and no caller-derived cache entry."""

from __future__ import annotations

import json
import sys
from types import ModuleType
from typing import Any

import pytest

from app.core.cache import CacheKeys, CacheService
from app.core.config import settings
from app.db import mongodb
from app.schemas.adhoc import AdhocAnalyzeRequest
from app.services.analysis.adhoc import run_adhoc_analysis
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
        "aggregate",
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

# Reaching MongoDB other than through the injected handle: the module-level accessor, a fresh
# client, or a GridFS bucket built from either.
_BYPASS_ENTRY_POINTS = ("get_database", "connect_to_mongo", "primary_gridfs_bucket")

# Upstream reference lists shared by every caller: the key names the source, never the payload.
_UPSTREAM_REFERENCE_CACHE_KEYS = frozenset(
    {
        CacheKeys.popular_packages("npm"),
        CacheKeys.popular_packages("pypi"),
        CacheKeys.kev_catalog(),
    }
)

_UNNAMED_COLLECTION = "a_collection_no_one_named"
_LEAK_ID = "leak"
_CALLER_DERIVED_CACHE_KEY = "osv2:0123456789abcdef"
_SEEDED_POPULAR_PYPI = ["requests", "flask", "django"]

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
            "bom-ref": "pkg:npm/expresss@4.18.2",
            "name": "expresss",
            "version": "4.18.2",
            "purl": "pkg:npm/expresss@4.18.2",
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
        {"ref": "pkg:pypi/requests@2.31.0", "dependsOn": ["pkg:npm/expresss@4.18.2"]},
        {"ref": "pkg:npm/expresss@4.18.2", "dependsOn": []},
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

_CALLGRAPH = {"nodes": [{"id": "app.handlers.run"}], "edges": []}

_ANALYZERS = [
    "license_compliance",
    "typosquatting",
    "crypto_weak_algorithm",
    "crypto_weak_key",
    "crypto_quantum_vulnerable",
    "crypto_certificate_lifecycle",
    "crypto_protocol_cipher",
]


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
        target = getattr(self._inner, attribute)
        if attribute in _COLLECTION_READS or not callable(target):
            return target

        def _record(*args: Any, **kwargs: Any) -> Any:
            self._writes.append(f"{self._name}.{attribute}")
            return target(*args, **kwargs)

        return _record


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


def assert_no_write_calls(db: _WriteRecordingDatabase) -> None:
    assert db.writes == [], f"ad-hoc analysis made write calls: {db.writes}"


# ── Net 2: MongoDB reached without the injected handle


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


def _rebind_everywhere(monkeypatch: pytest.MonkeyPatch, original: Any, replacement: Any) -> None:
    """Rebind by identity across sys.modules: a ``from x import y`` consumer holds its own reference."""
    for module in list(sys.modules.values()):
        if not isinstance(module, ModuleType):
            continue
        for attribute, value in list(vars(module).items()):
            if value is original:
                monkeypatch.setattr(module, attribute, replacement, raising=False)


@pytest.fixture
def bypass_attempts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    touched: list[str] = []
    for name in _BYPASS_ENTRY_POINTS:
        label = f"app.db.mongodb.{name}"
        _rebind_everywhere(monkeypatch, getattr(mongodb, name), _BypassTripwire(label, touched))
    monkeypatch.setattr(mongodb.db, "client", _TripwireClient(touched))
    return touched


# ── Net 3: Redis


class _RecordingRedis:
    """Minimal Redis stand-in that serves what it holds and records every key it is asked to write."""

    def __init__(self, store: dict[str, str], writes: list[str]) -> None:
        self._store = store
        self._writes = writes

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def mget(self, keys: list[str]) -> list[str | None]:
        return [self._store.get(key) for key in keys]

    async def exists(self, key: str) -> int:
        return int(key in self._store)

    async def ping(self) -> bool:
        return True

    def pipeline(self) -> _RecordingPipeline:
        return _RecordingPipeline(self)

    def record(self, key: str, value: str | None = None) -> None:
        self._writes.append(key)
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


def assert_no_caller_derived_cache_writes(written_keys: list[str]) -> None:
    """Upstream reference data may be cached; anything keyed off the posted payload may not."""
    leaked = [key for key in written_keys if _unprefixed(key) not in _UPSTREAM_REFERENCE_CACHE_KEYS]
    assert leaked == [], f"ad-hoc analysis cached caller-derived keys: {leaked}"


@pytest.fixture
def cache_writes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    writes: list[str] = []
    seeded = {f"{settings.CACHE_PREFIX}{CacheKeys.popular_packages('pypi')}": json.dumps(_SEEDED_POPULAR_PYPI)}
    client = _RecordingRedis(seeded, writes)

    async def _get_client(_self: CacheService) -> _RecordingRedis:
        return client

    async def _available(_self: CacheService) -> bool:
        return True

    monkeypatch.setattr(CacheService, "get_client", _get_client)
    monkeypatch.setattr(CacheService, "_ensure_available", _available)
    return writes


# ── The proof


def _full_request() -> AdhocAnalyzeRequest:
    return AdhocAnalyzeRequest(
        sboms=[_SBOM],
        scanners={"trufflehog": _TRUFFLEHOG, "opengrep": _OPENGREP, "bearer": _BEARER, "kics": _KICS},
        analyzers=_ANALYZERS,
        callgraph=_CALLGRAPH,
        apply_global_waivers=True,
    )


@pytest.mark.asyncio
async def test_adhoc_analysis_persists_nothing(bypass_attempts, cache_writes):
    db = _WriteRecordingDatabase()

    response = await run_adhoc_analysis(_full_request(), db)

    assert response.findings, "the run must actually produce findings, or the proof is vacuous"
    assert response.analyzers.ran, "the run must actually reach analyzers, or the proof is vacuous"
    assert cache_writes, "the run must actually reach Redis, or the cache net is vacuous"
    assert_no_write_calls(db)
    await assert_nothing_persisted(db)
    assert bypass_attempts == []
    assert_no_caller_derived_cache_writes(cache_writes)


@pytest.mark.asyncio
async def test_adhoc_analysis_persists_nothing_when_an_analyzer_fails(monkeypatch, bypass_attempts, cache_writes):
    from app.services.analysis import registry

    class _Boom:
        name = "license_compliance"

        async def analyze(self, sbom, settings=None, parsed_components=None):
            raise RuntimeError("upstream exploded")

    monkeypatch.setitem(registry.analyzers, "license_compliance", _Boom())

    db = _WriteRecordingDatabase()

    response = await run_adhoc_analysis(_full_request(), db)

    assert response.analyzers.errored, "the failure must reach the report, or the proof is vacuous"
    assert_no_write_calls(db)
    await assert_nothing_persisted(db)
    assert bypass_attempts == []
    assert_no_caller_derived_cache_writes(cache_writes)


# ── The proof's own detectors


@pytest.mark.asyncio
async def test_a_write_into_a_collection_no_one_named_is_caught():
    db = _WriteRecordingDatabase()

    await db[_UNNAMED_COLLECTION].insert_one({"_id": _LEAK_ID})

    assert db.writes == [f"{_UNNAMED_COLLECTION}.insert_one"]
    with pytest.raises(AssertionError, match=_UNNAMED_COLLECTION):
        await assert_nothing_persisted(db)


@pytest.mark.asyncio
async def test_a_write_that_leaves_no_document_behind_is_caught():
    db = _WriteRecordingDatabase()

    await db.scans.insert_one({"_id": _LEAK_ID})
    await db.scans.delete_one({"_id": _LEAK_ID})

    await assert_nothing_persisted(db)
    with pytest.raises(AssertionError, match="insert_one"):
        assert_no_write_calls(db)


def test_reaching_mongo_without_the_injected_handle_is_caught(bypass_attempts):
    from app.api import deps

    with pytest.raises(AssertionError):
        deps.get_database()

    assert bypass_attempts == ["app.db.mongodb.get_database"]


def test_a_caller_derived_cache_key_is_caught():
    assert_no_caller_derived_cache_writes([f"{settings.CACHE_PREFIX}{CacheKeys.popular_packages('npm')}"])

    with pytest.raises(AssertionError, match=_CALLER_DERIVED_CACHE_KEY):
        assert_no_caller_derived_cache_writes([f"{settings.CACHE_PREFIX}{_CALLER_DERIVED_CACHE_KEY}"])
