"""
Shared test fixtures and configuration.

Environment variables are set BEFORE any app imports to prevent
accidental connections to real databases.
"""

import os
import sys

# Ensure the backend app is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Override settings before any app code imports the settings singleton
os.environ["SECRET_KEY"] = "test-secret-key-for-unit-tests"
os.environ["ALGORITHM"] = "HS256"
os.environ["ACCESS_TOKEN_EXPIRE_MINUTES"] = "15"
os.environ["REFRESH_TOKEN_EXPIRE_DAYS"] = "1"
os.environ["MONGODB_URL"] = "mongodb://localhost:27017"
os.environ["DATABASE_NAME"] = "test_dependency_control"

import pytest  # noqa: E402

from tests.mocks.gitlab import make_gitlab_instance  # noqa: E402
from tests.mocks.github import make_github_instance  # noqa: E402


@pytest.fixture
def gitlab_instance_a():
    """Standard GitLab instance A for testing."""
    return make_gitlab_instance(
        id="instance-a-id",
        name="GitLab A",
        url="https://gitlab-a.com",
        access_token="glpat-token-a",
    )


@pytest.fixture
def gitlab_instance_b():
    """Standard GitLab instance B for testing."""
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
    """Standard GitHub instance A for testing."""
    return make_github_instance(
        id="gh-instance-a-id",
        name="GitHub.com",
        url="https://token.actions.githubusercontent.com",
    )


@pytest.fixture
def github_instance_b():
    """Standard GitHub instance B - GHES for testing."""
    return make_github_instance(
        id="gh-instance-b-id",
        name="GitHub Enterprise",
        url="https://github.corp.example.com/_services/token",
        github_url="https://github.corp.example.com",
        auto_create_projects=False,
    )


@pytest.fixture
def sample_purls():
    """Common PURL strings for testing."""
    return {
        "pypi": "pkg:pypi/requests@2.31.0",
        "npm": "pkg:npm/express@4.18.2",
        "npm_scoped": "pkg:npm/%40angular/core@16.0.0",
        "maven": "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        "go": "pkg:golang/github.com/gin-gonic/gin@1.9.1",
        "cargo": "pkg:cargo/serde@1.0.188",
        "nuget": "pkg:nuget/Newtonsoft.Json@13.0.3",
        "with_qualifiers": "pkg:pypi/requests@2.31.0?repository_url=https://pypi.org",
        "with_subpath": "pkg:npm/lodash@4.17.21#dist/lodash.min.js",
    }


@pytest.fixture
def admin_permissions():
    from app.core.permissions import PRESET_ADMIN

    return PRESET_ADMIN.copy()


@pytest.fixture
def user_permissions():
    from app.core.permissions import PRESET_USER

    return PRESET_USER.copy()


@pytest.fixture
def viewer_permissions():
    from app.core.permissions import PRESET_VIEWER

    return PRESET_VIEWER.copy()


@pytest.fixture
def cyclonedx_minimal():
    """Minimal valid CycloneDX SBOM."""
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
                "purl": "pkg:pypi/requests@2.31.0",
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
    """Minimal valid SPDX SBOM."""
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
                        "referenceLocator": "pkg:pypi/requests@2.31.0",
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
    """Minimal valid Syft SBOM."""
    return {
        "descriptor": {"name": "syft", "version": "0.100.0"},
        "source": {"type": "directory", "target": "/app"},
        "artifacts": [
            {
                "id": "artifact-1",
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
                "type": "python",
                "licenses": [{"value": "Apache-2.0"}],
                "locations": [{"path": "/app/requirements.txt"}],
            }
        ],
        "artifactRelationships": [],
    }
