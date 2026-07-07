"""Tests for GitHub instance API endpoints."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

MODULE = "app.api.v1.endpoints.github_instances"


def _make_repo_mock(**method_returns):
    """Create a mock GitHubInstanceRepository with configured async return values."""
    mock_repo = MagicMock()
    for method_name, return_value in method_returns.items():
        setattr(mock_repo, method_name, AsyncMock(return_value=return_value))
    return mock_repo


class TestGitHubInstancePagination:
    def test_pagination_response_page_reflects_requested_page(self, admin_user):
        """Regression: build_pagination_response must receive skip, not the page number.

        The GitHub list endpoint is a near-verbatim sibling of the GitLab one; the
        GitLab endpoint was fixed to pass ``skip`` but the GitHub copy still passed
        the 1-based ``page`` as the ``skip`` argument, so for page=2, size=100 the
        reported page collapsed to 1, breaking client-side pagination state.
        """
        from app.api.v1.endpoints.github_instances import list_instances

        mock_repo = _make_repo_mock(list_all=[], count_all=250)

        with patch(f"{MODULE}.GitHubInstanceRepository", return_value=mock_repo):
            result = asyncio.run(
                list_instances(
                    page=2,
                    size=100,
                    active_only=False,
                    db=MagicMock(),
                    current_user=admin_user,
                )
            )

        assert result["page"] == 2
        assert result["size"] == 100
        assert result["pages"] == 3
