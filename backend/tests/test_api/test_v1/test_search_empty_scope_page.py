"""An empty search answers page 1 like every other list, not page 0."""

from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.endpoints.analytics.search import search_dependencies_advanced, search_vulnerabilities
from app.core.permissions import ALL_PERMISSIONS
from app.models.user import User
from tests.mocks.fake_mongo import FakeDatabase

_USER = User(id="u1", username="u1", email="u1@test.com", permissions=list(ALL_PERMISSIONS))


@pytest.mark.asyncio
@pytest.mark.parametrize("search", [search_dependencies_advanced, search_vulnerabilities])
async def test_a_search_over_no_accessible_project_is_page_one(search):
    with patch("app.api.v1.endpoints.analytics.search.get_user_projects", AsyncMock(return_value=[])):
        response = await search(_USER, FakeDatabase(), q="lodash", skip=0, limit=50)

    assert (response.page, response.total, response.size) == (1, 0, 50)
