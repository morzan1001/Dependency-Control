"""Tests for database projection schemas (app.schemas.projections)."""

from datetime import datetime, timezone

from app.schemas.projections import CallgraphMinimal


class TestCallgraphMinimalImportMapFromModuleUsage:
    """import_map is inverted from module_usage, the only source the minimal projection loads."""

    def _minimal_projection_doc(self):
        return {
            "_id": "cg-1",
            "language": "python",
            "module_usage": {
                "requests": {
                    "module": "requests",
                    "import_locations": ["a.py", "b.py"],
                },
                "flask": {
                    "module": "flask",
                    "import_locations": ["a.py"],
                },
            },
        }

    def test_import_map_derived_from_module_usage(self):
        cg = CallgraphMinimal(**self._minimal_projection_doc())
        assert cg.import_map == {
            "a.py": ["requests", "flask"],
            "b.py": ["requests"],
        }

    def test_import_map_defaults_to_empty_dict_not_none(self):
        # Never None: build_reachability_summary calls len() on the serialized value.
        cg = CallgraphMinimal(_id="cg-1", language="javascript")
        assert cg.import_map == {}
        assert cg.model_dump(by_alias=True)["import_map"] == {}

    def test_import_map_is_live_on_serialized_projection(self):
        cg = CallgraphMinimal(**self._minimal_projection_doc())
        dumped = cg.model_dump(by_alias=True)
        assert len(dumped["import_map"]) == 2

    def test_reachability_fallback_sees_package_via_derived_map(self):
        from app.services.reachability_enrichment import _check_package_in_imports

        cg = CallgraphMinimal(**self._minimal_projection_doc())
        assert sorted(_check_package_in_imports("requests", cg.import_map)) == ["a.py", "b.py"]

    def test_uses_dict_key_as_module_name_when_module_field_missing(self):
        cg = CallgraphMinimal(
            _id="cg-1",
            module_usage={"numpy": {"import_locations": ["m.py"]}},
        )
        assert cg.import_map == {"m.py": ["numpy"]}

    def test_module_usage_entries_without_locations_are_skipped(self):
        cg = CallgraphMinimal(
            _id="cg-1",
            module_usage={
                "requests": {"module": "requests", "import_locations": []},
                "flask": {"module": "flask", "import_locations": ["a.py"]},
            },
        )
        assert cg.import_map == {"a.py": ["flask"]}


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
