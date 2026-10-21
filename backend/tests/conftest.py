import gc
import importlib
import os
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Override settings before any app code imports the settings singleton
os.environ["SECRET_KEY"] = "test-secret-key-for-unit-tests-long-enough-for-hs512-hmac-checks"
os.environ["ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "15"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "1"
os.environ["MONGODB_URL"] = "mongodb://localhost:27017"
os.environ["DATABASE_NAME"] = "test_dependency_control"

import pytest
from bson import ObjectId

from app.core.cache import CacheService
from app.models.user import User
from tests.helpers.auth import make_admin
from tests.helpers.permission_presets import PRESET_ADMIN, PRESET_USER, PRESET_VIEWER
from tests.mocks.fake_mongo import FakeDatabase
from tests.mocks.github import make_github_instance
from tests.mocks.gitlab import make_gitlab_instance

# CI sets this, so a missing native stack fails the run instead of skipping the PDF tests.
_WEASYPRINT_REQUIRED = os.environ.get("DC_REQUIRE_WEASYPRINT") == "1"


def _probe_weasyprint() -> bool:
    """Retrying WeasyPrint's Cairo/Pango dlopen inside a running asyncio loop segfaults, so the suite tries once."""
    if importlib.util.find_spec("weasyprint") is None:
        if _WEASYPRINT_REQUIRED:
            raise RuntimeError("weasyprint is not installed")
        return False
    try:
        importlib.import_module("weasyprint")
    except Exception:  # pragma: no cover - environment-dependent
        if _WEASYPRINT_REQUIRED:
            raise
        return False
    return True


WEASYPRINT_USABLE = _probe_weasyprint()

TEST_PURL_REQUESTS = "pkg:pypi/requests@2.31.0"


@pytest.fixture(autouse=True)
def _isolate_analytics_cache():
    from app.services.analytics.cache import get_analytics_cache, get_delta_cache

    get_analytics_cache().clear()
    get_delta_cache().clear()
    yield
    get_analytics_cache().clear()
    get_delta_cache().clear()


@pytest.fixture(autouse=True)
def _isolate_github_rate_limit_holds():
    """A rate-limit hold lasts per process and instance id, and the tests share both."""
    from app.services.github import _rate_limit_holds

    _rate_limit_holds.clear()
    yield
    _rate_limit_holds.clear()


@pytest.fixture
def db():
    return FakeDatabase()


@pytest.fixture
def gitlab_instance_a():
    return make_gitlab_instance(
        id="instance-a-id",
        name="GitLab A",
        url="https://gitlab-a.com",
        access_token="glpat-token-a",
    )


@pytest.fixture
def gitlab_instance_b():
    return make_gitlab_instance(
        id="instance-b-id",
        name="GitLab B",
        url="https://gitlab-b.com",
        access_token="glpat-token-b",
        auto_create_projects=False,
        sync_teams=False,
    )


@pytest.fixture
def github_instance_a():
    return make_github_instance(
        id="gh-instance-a-id",
        name="GitHub.com",
        url="https://token.actions.githubusercontent.com",
    )


@pytest.fixture
def github_instance_b():
    return make_github_instance(
        id="gh-instance-b-id",
        name="GitHub Enterprise",
        url="https://github.corp.example.com/_services/token",
        github_url="https://github.corp.example.com",
        auto_create_projects=False,
    )


@pytest.fixture
def sample_purls():
    return {
        "pypi": TEST_PURL_REQUESTS,
        "npm": "pkg:npm/express@4.18.2",
        "npm_scoped": "pkg:npm/%40angular/core@16.0.0",
        "maven": "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        "go": "pkg:golang/github.com/gin-gonic/gin@1.9.1",
        "cargo": "pkg:cargo/serde@1.0.188",
        "nuget": "pkg:nuget/Newtonsoft.Json@13.0.3",
        "with_qualifiers": "pkg:pypi/requests@2.31.0?repository_url=https://pypi.org",
        "with_subpath": "pkg:npm/lodash@4.17.21#dist/lodash.min.js",
    }


class _FakeGridFSBucket:
    """Motor's bucket refuses FakeDatabase, so each upload's bytes stay in that database's fs.files."""

    def __init__(self, db):
        self._files = db["fs.files"]

    async def upload_from_stream(self, filename, data, metadata=None):
        file_id = ObjectId()
        await self._files.insert_one({"_id": file_id, "filename": filename, "data": data, "metadata": metadata})
        return file_id

    async def open_download_stream(self, file_id):
        data = (await self._files.find_one({"_id": file_id}))["data"]
        return SimpleNamespace(read=AsyncMock(return_value=data))


@pytest.fixture
def fake_gridfs(monkeypatch):
    for module in (
        "app.services.gridfs_maintenance",
        "app.repositories.analysis_results",
        "app.repositories.callgraphs",
    ):
        monkeypatch.setattr(f"{module}.AsyncIOMotorGridFSBucket", _FakeGridFSBucket)


@pytest.fixture
def archive_env(monkeypatch):
    from tests.helpers.fake_s3 import FakeS3Client, fake_get_s3_client

    fake = FakeS3Client()
    monkeypatch.setattr("app.core.s3.get_s3_client", lambda: fake_get_s3_client(fake))
    monkeypatch.setattr("app.core.s3.is_archive_enabled", lambda: True)
    monkeypatch.setattr("app.services.archive.is_encryption_enabled", lambda: False)
    monkeypatch.setattr("app.core.s3.settings", SimpleNamespace(S3_BUCKET_NAME="test-bucket", S3_KEY_PREFIX=""))
    return fake


@pytest.fixture
def fake_cache():
    import fakeredis.aioredis

    svc = CacheService()
    svc._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    svc._pool = object()  # non-None so get_client() short-circuits to the fake
    svc._available = True
    return svc


async def cache_ttl(cache: CacheService, key: str) -> int:
    return await cache._client.ttl(cache._make_key(key))


@pytest.fixture
def tcp_redis(monkeypatch):
    """A Redis speaking RESP over a real socket, so the service builds its own connection pool."""
    import threading

    from fakeredis import TcpFakeServer

    from app.core.config import settings

    server = TcpFakeServer(("127.0.0.1", 0), server_type="redis")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    host, port = server.server_address[:2]
    monkeypatch.setattr(settings, "REDIS_URL", f"redis://{host}:{port}/0")
    yield
    server.shutdown()
    server.server_close()


@pytest.fixture
def automatic_gc_off():
    was_enabled = gc.isenabled()
    gc.disable()
    yield
    if was_enabled:
        gc.enable()


@pytest.fixture
def admin_user():
    return make_admin()


@pytest.fixture
def regular_user():
    return User(id="user-1", username="user", email="user@test.com", permissions=list(PRESET_USER))


@pytest.fixture
def viewer_user():
    return User(id="viewer-1", username="viewer", email="viewer@test.com", permissions=list(PRESET_VIEWER))


@pytest.fixture
def no_perms_user():
    return User(id="noperm-1", username="noperm", email="noperm@test.com", permissions=[])


@pytest.fixture
def admin_permissions():
    return PRESET_ADMIN.copy()


@pytest.fixture
def user_permissions():
    return PRESET_USER.copy()


@pytest.fixture
def viewer_permissions():
    return PRESET_VIEWER.copy()


@pytest.fixture
def cyclonedx_minimal():
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": [{"name": "trivy", "version": "0.50.0"}],
            "component": {
                "type": "application",
                "name": "my-app",
                "bom-ref": "root",
            },
        },
        "components": [
            {
                "type": "library",
                "name": "requests",
                "version": "2.31.0",
                "purl": TEST_PURL_REQUESTS,
                "bom-ref": "requests-ref",
            },
            {
                "type": "library",
                "name": "urllib3",
                "version": "2.0.7",
                "purl": "pkg:pypi/urllib3@2.0.7",
                "bom-ref": "urllib3-ref",
            },
        ],
        "dependencies": [
            {"ref": "root", "dependsOn": ["requests-ref"]},
            {"ref": "requests-ref", "dependsOn": ["urllib3-ref"]},
            {"ref": "urllib3-ref", "dependsOn": []},
        ],
    }


@pytest.fixture
def spdx_minimal():
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "test-sbom",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-requests",
                "name": "requests",
                "versionInfo": "2.31.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": TEST_PURL_REQUESTS,
                    }
                ],
                "licenseConcluded": "Apache-2.0",
                "downloadLocation": "https://pypi.org/project/requests/2.31.0/",
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-Package-requests",
                "relationshipType": "DESCRIBES",
            }
        ],
    }


@pytest.fixture
def syft_minimal():
    return {
        "descriptor": {"name": "syft", "version": "0.100.0"},
        "source": {"type": "directory", "target": "/app"},
        "artifacts": [
            {
                "id": "artifact-1",
                "name": "requests",
                "version": "2.31.0",
                "purl": TEST_PURL_REQUESTS,
                "type": "python",
                "licenses": [{"value": "Apache-2.0"}],
                "locations": [{"path": "/app/requirements.txt"}],
            }
        ],
        "artifactRelationships": [],
    }
