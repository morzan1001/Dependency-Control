"""End-to-end callgraph upload: the exact payload each CI job posts, the stored document, the reachability verdict.

Payload shapes are transcribed from ``dependency-control-pipeline-templates/callgraph.yaml``
(the shared upload anchor plus the js/python/go/java producers).
"""

import copy
import uuid
from datetime import datetime, timezone
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.api.v1.endpoints import callgraph as callgraph_endpoint
from app.core.constants import CALLGRAPH_MAX_ENTRIES
from app.core.permissions import Permissions
from app.models.project import Project
from tests.helpers.auth import bearer_headers
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

DEPS = "app.api.deps"

_PROJECT_ID = "proj-cg"
_PIPELINE_ID = 776655
_BRANCH = "main"
_COMMIT = "9f1c0d3a2b5e4f6a7c8d9e0f1a2b3c4d5e6f7a8b"

# uuid5 over "<project>-<pipeline>-<commit>" is the contract between the upload endpoint
# and the scan the CI job produced; spelled out here so a change to it fails loudly.
_SCAN_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{_PROJECT_ID}-{_PIPELINE_ID}-{_COMMIT}"))

# Each oversized payload below walks exactly one entry more than this.
_SMALL_ENTRY_LIMIT = 3


def _envelope(fmt: str, language: str | None, data: dict) -> dict:
    """The body built by the ``.upload-callgraph-script`` anchor."""
    body = {
        "format": fmt,
        "language": language,
        "pipeline_id": _PIPELINE_ID,
        "branch": _BRANCH,
        "commit_hash": _COMMIT,
        "data": data,
    }
    if language is None:
        del body["language"]
    return body


# --- producer payloads -------------------------------------------------------

# madge --json --include-npm, with package.json deps+devDeps merged in by the job.
_MADGE_DATA = {
    "index.js": [
        "node_modules/lodash/lodash.js",
        "node_modules/@babel/runtime/helpers/esm/extends.js",
        "src/util.js",
    ],
    "src/util.js": ["node_modules/express/index.js"],
    "node_modules/lodash/lodash.js": [],
    "__analyzed_modules__": ["@babel/runtime", "express", "lodash"],
}

# stdlib ast import scanner + importlib.metadata.distributions()
_PYTHON_DATA = {
    "imports": [
        {"module": "requests", "file": "app/client.py", "line": 3, "symbols": []},
        {"module": "urllib3.util.retry", "file": "app/client.py", "line": 4, "symbols": ["Retry"]},
        {"module": "app.config", "file": "app/client.py", "line": 5, "symbols": ["settings"]},
    ],
    "analyzed_modules": ["PyYAML", "requests", "urllib3"],
}

# go list -deps -json ./... + go list -m all
_GO_DATA = {
    "imports": [
        {"module": "github.com/gin-gonic/gin", "file": "cmd/api", "line": 0, "symbols": []},
        {"module": "github.com/sirupsen/logrus", "file": "internal/log", "line": 0, "symbols": []},
    ],
    "analyzed_modules": [
        "github.com/gin-gonic/gin",
        "github.com/sirupsen/logrus",
        "golang.org/x/sys",
    ],
}

# jdeps -verbose:class -R; analyzed_modules stays empty while DC_JVM_PUBLISH_COVERAGE is "false"
_JAVA_DATA = {
    "imports": [
        {
            "module": "com.fasterxml.jackson.core:jackson-databind",
            "file": "com.acme.api.OrderController",
            "line": 0,
            "symbols": ["JsonNode", "ObjectMapper"],
        },
        {
            "module": "com.google.guava:guava",
            "file": "com.acme.api.OrderController",
            "line": 0,
            "symbols": ["ImmutableList"],
        },
    ],
    "analyzed_modules": [],
}

_PRODUCERS = [
    pytest.param(
        _envelope("madge", "javascript", _MADGE_DATA),
        "javascript",
        {"lodash", "@babel/runtime", "express"},
        ["@babel/runtime", "express", "lodash"],
        id="js-madge",
    ),
    pytest.param(
        _envelope("generic", "python", _PYTHON_DATA),
        "python",
        # A first-party absolute import ("app.config") is indistinguishable from a
        # distribution at parse time, so it gets a usage entry; only analyzed_modules gates
        # the unreachable verdict.
        {"requests", "urllib3", "app"},
        ["pyyaml", "requests", "urllib3"],
        id="python-ast",
    ),
    pytest.param(
        _envelope("generic", "go", _GO_DATA),
        "go",
        {"github.com/gin-gonic/gin", "github.com/sirupsen/logrus"},
        ["github.com/gin-gonic/gin", "github.com/sirupsen/logrus", "golang.org/x/sys"],
        id="go-list",
    ),
    pytest.param(
        _envelope("generic", "java", _JAVA_DATA),
        "java",
        {"com.fasterxml.jackson.core:jackson-databind", "com.google.guava:guava"},
        [],
        id="java-jdeps",
    ),
]


# --- fixtures ----------------------------------------------------------------


@pytest_asyncio.fixture
async def db():
    return FakeDatabase()


@pytest_asyncio.fixture
async def client(db):
    """The real app with only the database swapped for the in-process fake."""
    from app.api.deps import get_database
    from app.main import app

    async def _get_database():
        return db

    app.dependency_overrides[get_database] = _get_database
    await db.projects.insert_one(Project(id=_PROJECT_ID, name="cg-project").model_dump(by_alias=True))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.pop(get_database, None)


def _ci_credentials(resolved_project_id: str = _PROJECT_ID):
    """Stand in for the Job-Token exchange, resolving to ``resolved_project_id``."""
    return patch(
        f"{DEPS}.get_project_for_ingest",
        new_callable=AsyncMock,
        return_value=Project(id=resolved_project_id, name="cg-project"),
    )


async def _upload(client, payload: dict, *, resolved_project_id: str = _PROJECT_ID):
    with _ci_credentials(resolved_project_id):
        return await client.post(
            f"/api/v1/projects/{_PROJECT_ID}/callgraph",
            json=payload,
            headers={"Job-Token": "gitlab.oidc.token"},
        )


async def _seed_user(db, username: str, permissions: list[str]) -> dict[str, str]:
    await db.users.insert_one(
        {
            "_id": username,
            "username": username,
            "email": f"{username}@test.com",
            "permissions": list(permissions),
            "is_active": True,
        }
    )
    return bearer_headers(username, permissions)


async def _add_member(db, user_id: str, role: str) -> None:
    await db.projects.update_one(
        {"_id": _PROJECT_ID},
        {"$set": {"members": [{"user_id": user_id, "role": role}]}},
    )


# --- producers ---------------------------------------------------------------


class TestProducerUploads:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(("payload", "language", "module_keys", "analyzed"), _PRODUCERS)
    async def test_producer_payload_is_stored(self, client, db, payload, language, module_keys, analyzed):
        response = await _upload(client, payload)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["project_id"] == _PROJECT_ID
        assert body["modules_detected"] == len(module_keys)
        assert body["analyzed_modules_count"] == len(analyzed)
        assert body["warnings"] == []

        stored = await db.callgraphs.find_one({"project_id": _PROJECT_ID, "language": language})
        assert stored is not None
        assert stored["language"] == language
        assert set(stored["module_usage"]) == module_keys
        assert stored["analyzed_modules"] == analyzed
        assert stored["scan_id"] == _SCAN_ID
        assert stored["pipeline_id"] == _PIPELINE_ID
        assert stored["branch"] == _BRANCH
        assert stored["commit_hash"] == _COMMIT

    @pytest.mark.asyncio
    async def test_python_symbols_survive_to_module_usage(self, client, db):
        """The AST producer is the only one shipping symbols, which is what buys symbol-level verdicts."""
        await _upload(client, _envelope("generic", "python", _PYTHON_DATA))

        stored = await db.callgraphs.find_one({"project_id": _PROJECT_ID})
        assert stored["module_usage"]["urllib3"]["used_symbols"] == ["Retry"]
        assert stored["module_usage"]["urllib3"]["import_locations"] == ["app/client.py"]

    @pytest.mark.asyncio
    async def test_java_publishes_no_coverage_universe_by_default(self, client, db):
        await _upload(client, _envelope("generic", "java", _JAVA_DATA))

        stored = await db.callgraphs.find_one({"project_id": _PROJECT_ID})
        assert stored["analyzed_modules"] == []


# --- authentication and authorization ----------------------------------------


class TestUploadAuthorization:
    @pytest.mark.asyncio
    async def test_ci_credentials_for_another_project_are_forbidden(self, client, db):
        response = await _upload(client, _envelope("generic", "go", _GO_DATA), resolved_project_id="someone-else")

        assert response.status_code == 403
        assert await db.callgraphs.count_documents({}) == 0

    @pytest.mark.asyncio
    async def test_missing_credentials_are_unauthorized(self, client, db):
        response = await client.post(
            f"/api/v1/projects/{_PROJECT_ID}/callgraph",
            json=_envelope("generic", "go", _GO_DATA),
        )

        assert response.status_code == 401
        assert response.json()["detail"] == "Missing authentication credentials"
        assert await db.callgraphs.count_documents({}) == 0

    @pytest.mark.asyncio
    async def test_plain_member_cannot_upload(self, client, db):
        headers = await _seed_user(db, "viewer-1", [Permissions.PROJECT_READ])
        await _add_member(db, "viewer-1", "viewer")

        response = await client.post(
            f"/api/v1/projects/{_PROJECT_ID}/callgraph",
            json=_envelope("generic", "go", _GO_DATA),
            headers=headers,
        )

        assert response.status_code == 403
        assert await db.callgraphs.count_documents({}) == 0

    @pytest.mark.asyncio
    async def test_plain_member_cannot_delete(self, client, db):
        await _upload(client, _envelope("generic", "go", _GO_DATA))
        headers = await _seed_user(db, "viewer-2", [Permissions.PROJECT_READ])
        await _add_member(db, "viewer-2", "viewer")

        response = await client.delete(f"/api/v1/projects/{_PROJECT_ID}/callgraph", headers=headers)

        assert response.status_code == 403
        assert await db.callgraphs.count_documents({}) == 1


# --- payload validation ------------------------------------------------------


class TestPayloadValidation:
    @pytest.mark.asyncio
    async def test_generic_payload_without_language_is_rejected(self, client, db):
        response = await _upload(client, _envelope("generic", None, _GO_DATA))

        assert response.status_code == 400
        assert response.json()["detail"] == "'language' is required for 'generic' callgraph payloads"
        assert await db.callgraphs.count_documents({}) == 0

    @pytest.mark.asyncio
    async def test_payload_over_the_entry_limit_is_rejected(self, client, db):
        oversized = {
            "imports": [
                {"module": f"example.com/m{i}", "file": f"pkg/p{i}", "line": 0, "symbols": []}
                for i in range(CALLGRAPH_MAX_ENTRIES + 1)
            ],
            "analyzed_modules": [],
        }

        response = await _upload(client, _envelope("generic", "go", oversized))

        assert response.status_code == 413
        detail = response.json()["detail"]
        assert str(CALLGRAPH_MAX_ENTRIES) in detail
        assert str(CALLGRAPH_MAX_ENTRIES + 1) in detail
        assert await db.callgraphs.count_documents({}) == 0

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "oversized",
        [
            pytest.param(
                {"imports": [{"module": "lodash", "file": "src/a.js", "symbols": ["map", "get", "set"]}]},
                id="symbols",
            ),
            pytest.param({"src/a.js": ["lodash", "express"], "src/b.js": ["react", "vue"]}, id="madge-dependencies"),
            pytest.param(
                {"imports": [], "analyzed_modules": ["lodash", "express", "react", "vue"]}, id="coverage-universe"
            ),
        ],
    )
    async def test_everything_the_parser_walks_counts_and_is_refused_before_parsing(
        self, client, db, monkeypatch, oversized
    ):
        monkeypatch.setattr("app.api.v1.endpoints.callgraph.CALLGRAPH_MAX_ENTRIES", _SMALL_ENTRY_LIMIT)
        parse = MagicMock()
        monkeypatch.setattr("app.api.v1.endpoints.callgraph._parse_callgraph", parse)

        response = await _upload(client, _envelope("auto", "javascript", oversized))

        assert response.status_code == 413
        assert f"exceeds the limit of {_SMALL_ENTRY_LIMIT}" in response.json()["detail"]
        assert parse.call_count == 0
        assert await db.callgraphs.count_documents({}) == 0

    @pytest.mark.asyncio
    async def test_the_parse_runs_off_the_event_loop(self, client, db, monkeypatch):
        threads = []
        real_parse = callgraph_endpoint._parse_callgraph

        def _recording_parse(*args):
            threads.append(threading.current_thread())
            return real_parse(*args)

        monkeypatch.setattr("app.api.v1.endpoints.callgraph._parse_callgraph", _recording_parse)

        response = await _upload(client, _envelope("generic", "python", _PYTHON_DATA))

        assert response.status_code == 200, response.text
        assert threads
        assert threading.main_thread() not in threads


class TestReupload:
    @pytest.mark.asyncio
    async def test_reupload_of_the_same_scan_keeps_created_at(self, client, db):
        await _upload(client, _envelope("generic", "python", _PYTHON_DATA))
        first = await db.callgraphs.find_one({"project_id": _PROJECT_ID})

        grown = {
            "imports": [*_PYTHON_DATA["imports"], {"module": "boto3", "file": "app/s3.py", "line": 1, "symbols": []}],
            "analyzed_modules": [*_PYTHON_DATA["analyzed_modules"], "boto3"],
        }
        await _upload(client, _envelope("generic", "python", grown))

        assert await db.callgraphs.count_documents({}) == 1
        second = await db.callgraphs.find_one({"project_id": _PROJECT_ID})
        assert second["created_at"] == first["created_at"]
        assert second["_id"] == first["_id"]
        assert "boto3" in second["module_usage"]


class TestModuleUsageEndpoint:
    @pytest.mark.asyncio
    async def test_modules_endpoint_serialises_a_non_empty_usage_map(self, client, db):
        await _upload(client, _envelope("madge", "javascript", _MADGE_DATA))
        headers = await _seed_user(db, "admin-1", PRESET_ADMIN)

        response = await client.get(f"/api/v1/projects/{_PROJECT_ID}/callgraph/modules", headers=headers)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["language"] == "javascript"
        assert body["modules"], "a non-empty module_usage must survive serialisation"
        for module in body["modules"]:
            assert module["name"] == module["module"]
        assert {m["module"] for m in body["modules"]} == {"lodash", "@babel/runtime", "express"}


# --- reachability ------------------------------------------------------------


def _finding(finding_id: str, component: str, *, scan_id: str = _SCAN_ID, project_id: str = _PROJECT_ID) -> dict:
    return {
        "_id": f"f-{finding_id}",
        "id": finding_id,
        "finding_id": finding_id,
        "scan_id": scan_id,
        "project_id": project_id,
        "type": "vulnerability",
        "severity": "HIGH",
        "component": component,
        "version": "1.0.0",
        "description": f"{finding_id} in {component}",
        "scanners": ["osv"],
        "waived": False,
        "details": {"risk_score": 40.0, "vulnerabilities": [{"id": finding_id, "severity": "HIGH"}]},
    }


async def _seed_scan_with_findings(db) -> None:
    await db.scans.insert_one(
        {
            "_id": _SCAN_ID,
            "project_id": _PROJECT_ID,
            "branch": _BRANCH,
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
            "reachability_pending": True,
        }
    )
    await db.findings.insert_one(_finding("CVE-PY", "requests"))
    await db.findings.insert_one(_finding("CVE-JS", "lodash"))
    for name, ecosystem in (("requests", "pypi"), ("lodash", "npm")):
        await db.dependencies.insert_one(
            {
                "_id": f"dep-{name}",
                "scan_id": _SCAN_ID,
                "name": name,
                "version": "1.0.0",
                "type": ecosystem,
                "purl": f"pkg:{ecosystem}/{name}@1.0.0",
            }
        )


class TestReachabilityVerdicts:
    @pytest.mark.asyncio
    async def test_second_language_upload_is_also_applied(self, client, db):
        """Every upload re-runs enrichment, so language two is not silently dropped after language one cleared the flag."""
        await _seed_scan_with_findings(db)

        await _upload(client, _envelope("generic", "python", _PYTHON_DATA))

        js_finding = await db.findings.find_one({"_id": "f-CVE-JS"})
        assert js_finding["reachable"] is None, "the python callgraph must not judge an npm package"

        # Production clears the flag with $unset, which the in-process fake ignores; mirror the
        # cleared state so the second upload faces the same scan the real one would.
        await db.scans.update_one({"_id": _SCAN_ID}, {"$set": {"reachability_pending": False}})

        await _upload(client, _envelope("madge", "javascript", _MADGE_DATA))

        js_finding = await db.findings.find_one({"_id": "f-CVE-JS"})
        assert js_finding["reachable"] is True
        assert js_finding["reachability_level"] == "import"

        py_finding = await db.findings.find_one({"_id": "f-CVE-PY"})
        assert py_finding["reachable"] is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", ["pending", "processing"])
    async def test_an_upload_for_a_scan_under_analysis_is_left_to_that_analysis(self, client, db, status):
        """Its findings are about to be replaced, so enriching them now would lose the verdicts."""
        await _seed_scan_with_findings(db)
        await db.scans.update_one({"_id": _SCAN_ID}, {"$set": {"status": status, "reachability_pending": False}})

        await _upload(client, _envelope("generic", "python", _PYTHON_DATA))

        assert (await db.scans.find_one({"_id": _SCAN_ID}))["reachability_pending"] is True
        assert "reachable" not in await db.findings.find_one({"_id": "f-CVE-PY"})

    @pytest.mark.asyncio
    async def test_analyzed_but_unimported_package_is_unreachable(self, client, db):
        await _seed_scan_with_findings(db)
        data = {
            "imports": [{"module": "urllib3", "file": "app/client.py", "line": 1, "symbols": []}],
            "analyzed_modules": ["requests", "urllib3"],
        }

        await _upload(client, _envelope("generic", "python", data))

        py_finding = await db.findings.find_one({"_id": "f-CVE-PY"})
        assert py_finding["reachable"] is False
        assert py_finding["details"]["adjusted_risk_score"] < 40.0

    @pytest.mark.asyncio
    async def test_package_outside_the_coverage_universe_stays_unknown(self, client, db):
        await _seed_scan_with_findings(db)
        data = {
            "imports": [{"module": "urllib3", "file": "app/client.py", "line": 1, "symbols": []}],
            "analyzed_modules": [],
        }

        await _upload(client, _envelope("generic", "python", data))

        py_finding = await db.findings.find_one({"_id": "f-CVE-PY"})
        assert py_finding["reachable"] is None
        assert py_finding["details"]["adjusted_risk_score"] == 40.0


_FOREIGN_PROJECT_ID = "proj-foreign"
_FOREIGN_SCAN_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{_FOREIGN_PROJECT_ID}-{_PIPELINE_ID}-{_COMMIT}"))


async def _seed_foreign_project(db) -> None:
    await db.projects.insert_one(
        {
            "_id": _FOREIGN_PROJECT_ID,
            "name": "foreign-project",
            "latest_scan_id": _FOREIGN_SCAN_ID,
            "stats": {"high": 1},
        }
    )
    await db.scans.insert_one(
        {
            "_id": _FOREIGN_SCAN_ID,
            "project_id": _FOREIGN_PROJECT_ID,
            "branch": _BRANCH,
            "status": "completed",
            "created_at": datetime.now(timezone.utc),
            "reachability_pending": True,
            "stats": {"high": 1},
        }
    )
    await db.findings.insert_one(
        _finding("CVE-FOREIGN", "requests", scan_id=_FOREIGN_SCAN_ID, project_id=_FOREIGN_PROJECT_ID)
    )
    await db.dependencies.insert_one(
        {
            "_id": "dep-foreign-requests",
            "scan_id": _FOREIGN_SCAN_ID,
            "project_id": _FOREIGN_PROJECT_ID,
            "name": "requests",
            "version": "1.0.0",
            "type": "pypi",
            "purl": "pkg:pypi/requests@1.0.0",
        }
    )


class TestForeignScanId:
    @pytest.mark.asyncio
    async def test_a_scan_id_in_the_body_cannot_reach_another_projects_scan(self, client, db):
        await _seed_foreign_project(db)
        # The fake hands out its live documents, so a snapshot has to be a copy.
        project_before = copy.deepcopy(await db.projects.find_one({"_id": _FOREIGN_PROJECT_ID}))
        scan_before = copy.deepcopy(await db.scans.find_one({"_id": _FOREIGN_SCAN_ID}))
        finding_before = copy.deepcopy(await db.findings.find_one({"_id": "f-CVE-FOREIGN"}))
        # Analysed but never imported: exactly the payload that would turn the finding unreachable.
        payload = {
            **_envelope("generic", "python", {"imports": [], "analyzed_modules": ["requests"]}),
            "scan_id": _FOREIGN_SCAN_ID,
        }

        response = await _upload(client, payload)

        assert response.status_code == 200, response.text
        assert await db.findings.find_one({"_id": "f-CVE-FOREIGN"}) == finding_before
        assert await db.scans.find_one({"_id": _FOREIGN_SCAN_ID}) == scan_before
        assert await db.projects.find_one({"_id": _FOREIGN_PROJECT_ID}) == project_before
        assert await db.analysis_results.count_documents({"scan_id": _FOREIGN_SCAN_ID}) == 0
        assert await db.callgraphs.count_documents({"scan_id": _FOREIGN_SCAN_ID}) == 0
        stored = await db.callgraphs.find_one({"project_id": _PROJECT_ID})
        assert stored["scan_id"] == _SCAN_ID
