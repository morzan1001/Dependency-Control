"""get_dependency_details finds a package's enrichment by any spelling of its purl, or by its name."""

import pytest

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


@pytest.mark.asyncio
@pytest.mark.parametrize("asked_for", [f"{_PURL}?type=jar#sub", "LOG4J-core"], ids=["qualified-purl", "name-any-case"])
async def test_the_enrichment_is_found_by_purl_variant_or_by_name(asked_for):
    db = FakeDatabase()
    db.dependency_enrichments._docs["e-1"] = {"_id": "e-1", "purl": _PURL, "name": "log4j-core", "version": "2.14.1"}
    admin = User(id="u-admin", username="admin", email="admin@test.com", permissions=PRESET_ADMIN)

    result = await ChatToolRegistry().execute_tool("get_dependency_details", {"dependency_name": asked_for}, admin, db)

    assert result["dependency"]["purl"] == _PURL


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stored", "asked_for"),
    [
        # Trivy's SPDX output names a Maven package "group:artifact"; the parser keeps that name.
        ("org.apache.logging.log4j:log4j-core", "log4j-core"),
        ("org.apache.logging.log4j:log4j-core", "LOG4J-core"),
        ("github.com/google/uuid", "google/uuid"),
    ],
)
async def test_a_bare_name_finds_the_package_stored_under_its_qualified_name(stored, asked_for):
    db = FakeDatabase()
    db.dependency_enrichments._docs["e-1"] = {"_id": "e-1", "purl": _PURL, "name": stored, "version": "2.14.1"}
    admin = User(id="u-admin", username="admin", email="admin@test.com", permissions=PRESET_ADMIN)

    result = await ChatToolRegistry().execute_tool("get_dependency_details", {"dependency_name": asked_for}, admin, db)

    assert result["dependency"]["name"] == stored


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stored", "purl", "asked_for"),
    [
        ("@angular/core", "pkg:npm/%40angular/core@17.0.0", "core"),
        ("requests-toolbelt", "pkg:pypi/requests-toolbelt@1.0.0", "toolbelt"),
    ],
    ids=["npm-scope", "suffix"],
)
async def test_a_name_does_not_find_a_package_it_only_ends_without_a_qualifier(stored, purl, asked_for):
    db = FakeDatabase()
    db.dependency_enrichments._docs["e-1"] = {"_id": "e-1", "purl": purl, "name": stored}
    admin = User(id="u-admin", username="admin", email="admin@test.com", permissions=PRESET_ADMIN)

    result = await ChatToolRegistry().execute_tool("get_dependency_details", {"dependency_name": asked_for}, admin, db)

    assert "dependency" not in result


@pytest.mark.asyncio
@pytest.mark.parametrize("asked_for", ["requests", "pkg:pypi/requests"], ids=["whole-name", "versionless-purl"])
async def test_a_name_or_versionless_purl_finds_that_package_not_one_containing_it(asked_for):
    db = FakeDatabase()
    # Stored first, so a substring match meets the wrong package before the right one.
    for _id, name in (("e-toolbelt", "requests-toolbelt"), ("e-requests", "requests")):
        db.dependency_enrichments._docs[_id] = {
            "_id": _id,
            "purl": f"pkg:pypi/{name}@2.31.0",
            "name": name,
            "version": "2.31.0",
        }
    admin = User(id="u-admin", username="admin", email="admin@test.com", permissions=PRESET_ADMIN)

    result = await ChatToolRegistry().execute_tool("get_dependency_details", {"dependency_name": asked_for}, admin, db)

    assert result["dependency"]["purl"] == "pkg:pypi/requests@2.31.0"
