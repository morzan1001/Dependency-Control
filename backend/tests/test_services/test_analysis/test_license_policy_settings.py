"""A scan grades licences under the policy the project settings page shows and saves."""

import pytest

from app.models.finding import Severity
from app.models.project import Project
from app.models.system import SystemSettings
from app.repositories.projects import ProjectRepository
from app.services.analysis.engine import _build_settings_resolver, _load_project_settings_overrides
from app.services.analyzers.license_compliance.analyzer import LicenseAnalyzer
from app.services.sbom_parser import parse_sbom
from tests.mocks.fake_mongo import FakeDatabase

_GPL_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "name": "gpl-lib",
            "version": "1.0",
            "purl": "pkg:pypi/gpl-lib@1.0",
            "licenses": [{"license": {"id": "GPL-3.0-only"}}],
        }
    ],
}


@pytest.mark.asyncio
async def test_a_stored_legacy_license_policy_does_not_override_the_saved_settings():
    """A top-level license_policy of internal_only leaves GPL graded HIGH under the saved distributed policy."""
    db = FakeDatabase()
    doc = Project(
        id="p1",
        name="P",
        analyzer_settings={"license_compliance": {"distribution_model": "distributed"}},
    ).model_dump(by_alias=True)
    db.projects._docs["p1"] = {**doc, "license_policy": {"distribution_model": "internal_only"}}

    analyzer_settings = await _load_project_settings_overrides("p1", ProjectRepository(db))
    settings = _build_settings_resolver(SystemSettings(), analyzer_settings)("license_compliance")
    parsed = [dep.model_dump() for dep in parse_sbom(_GPL_SBOM).dependencies]
    result = await LicenseAnalyzer().analyze(_GPL_SBOM, settings, parsed)

    assert [issue["severity"] for issue in result["license_issues"]] == [Severity.HIGH.value]
