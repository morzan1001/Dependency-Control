"""Tests for database projection schemas (app.schemas.projections)."""

from datetime import datetime, timezone

from app.schemas.projections import CallgraphMinimal


class TestCallgraphMinimalCoverageFields:
    def test_analyzed_modules_and_created_at_are_loaded(self):
        created = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
        cg = CallgraphMinimal(
            _id="cg-1",
            language="python",
            analyzed_modules=["requests", "urllib3"],
            created_at=created,
        )
        assert cg.analyzed_modules == ["requests", "urllib3"]
        assert cg.created_at == created

    def test_coverage_fields_default_to_empty_and_none(self):
        cg = CallgraphMinimal(_id="cg-1", language="python")
        assert cg.analyzed_modules == []
        assert cg.created_at is None
