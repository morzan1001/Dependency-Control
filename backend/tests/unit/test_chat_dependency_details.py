"""get_dependency_details finds a package's enrichment by any spelling of its purl, or by its name."""

import pytest

from app.models.user import User
from app.services.chat.tools import ChatToolRegistry
from tests.helpers.permission_presets import PRESET_ADMIN
from tests.mocks.fake_mongo import FakeDatabase

_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


@pytest.mark.asyncio
@pytest.mark.parametrize("asked_for", [f"{_PURL}?type=jar#sub", "LOG4J-core"], ids=["qualified-purl", "name-substring"])
async def test_the_enrichment_is_found_by_purl_variant_or_by_name(asked_for):
    db = FakeDatabase()
    db.dependency_enrichments._docs["e-1"] = {"_id": "e-1", "purl": _PURL, "name": "log4j-core", "version": "2.14.1"}
    admin = User(id="u-admin", username="admin", email="admin@test.com", permissions=PRESET_ADMIN)

    result = await ChatToolRegistry().execute_tool("get_dependency_details", {"dependency_name": asked_for}, admin, db)

    assert result["dependency"]["purl"] == _PURL
