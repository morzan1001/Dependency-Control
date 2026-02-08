"""Tests for pagination helper."""

from app.api.v1.helpers.pagination import build_pagination_response


class TestBuildPaginationResponse:
    def test_first_page(self):
        result = build_pagination_response(["a", "b"], total=25, skip=0, limit=10)
        assert result["page"] == 1
        assert result["pages"] == 3
        assert result["total"] == 25
        assert result["size"] == 10

    def test_second_page(self):
        result = build_pagination_response(["c", "d"], total=25, skip=10, limit=10)
        assert result["page"] == 2

    def test_last_page(self):
        result = build_pagination_response(["e"], total=25, skip=20, limit=10)
        assert result["page"] == 3

    def test_single_page(self):
        result = build_pagination_response(["a"], total=5, skip=0, limit=10)
        assert result["pages"] == 1

    def test_empty_results(self):
        result = build_pagination_response([], total=0, skip=0, limit=10)
        assert result["page"] == 1
        assert result["pages"] == 0
        assert result["items"] == []

    def test_limit_zero_safe(self):
        result = build_pagination_response([], total=10, skip=0, limit=0)
        assert result["page"] == 1
        assert result["pages"] == 0

    def test_items_preserved(self):
        items = [{"id": 1}, {"id": 2}]
        result = build_pagination_response(items, total=2, skip=0, limit=10)
        assert result["items"] == items

    def test_exact_page_boundary(self):
        result = build_pagination_response([], total=20, skip=0, limit=10)
        assert result["pages"] == 2
