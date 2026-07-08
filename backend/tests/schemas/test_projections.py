"""Tests for database projection schemas (app.schemas.projections)."""

from app.schemas.projections import CallgraphMinimal


class TestCallgraphMinimalImportMap:
    """import_map is derived as {file: [modules]} from the persisted imports list."""

    def test_import_map_derived_from_imports(self):
        cg = CallgraphMinimal(
            _id="cg-1",
            language="python",
            imports=[
                {"module": "requests", "file": "a.py", "line": 1},
                {"module": "flask", "file": "a.py", "line": 2},
                {"module": "requests", "file": "b.py", "line": 5},
            ],
        )
        assert cg.import_map == {
            "a.py": ["requests", "flask"],
            "b.py": ["requests"],
        }

    def test_import_map_defaults_to_empty_dict_not_none(self):
        # Never None: build_reachability_summary calls len() on the serialized value.
        cg = CallgraphMinimal(_id="cg-1", language="javascript")
        assert cg.import_map == {}
        assert cg.model_dump(by_alias=True)["import_map"] == {}

    def test_explicit_import_map_is_preserved(self):
        cg = CallgraphMinimal(
            _id="cg-1",
            import_map={"x.py": ["foo"]},
            imports=[{"module": "bar", "file": "y.py", "line": 1}],
        )
        assert cg.import_map == {"x.py": ["foo"]}

    def test_import_entries_missing_file_or_module_are_skipped(self):
        cg = CallgraphMinimal(
            _id="cg-1",
            imports=[
                {"module": "requests", "file": "a.py", "line": 1},
                {"module": "", "file": "a.py", "line": 2},
                {"file": "b.py", "line": 3},
                {"module": "flask", "line": 4},
            ],
        )
        assert cg.import_map == {"a.py": ["requests"]}


class TestCallgraphMinimalImportMapFromModuleUsage:
    """import_map derives from module_usage under the minimal DB projection, which omits raw imports."""

    def _minimal_projection_doc(self):
        # Mirrors the minimal projection: module_usage keyed by module name, no raw imports list.
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

    def test_import_map_derived_from_module_usage_when_imports_absent(self):
        cg = CallgraphMinimal(**self._minimal_projection_doc())
        assert cg.import_map == {
            "a.py": ["requests", "flask"],
            "b.py": ["requests"],
        }

    def test_total_imports_stat_is_live_on_serialized_projection(self):
        # import_map length (importing-file count) is non-zero on the serialized minimal projection.
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

    def test_explicit_imports_take_precedence_over_module_usage(self):
        cg = CallgraphMinimal(
            _id="cg-1",
            imports=[{"module": "bar", "file": "y.py", "line": 1}],
            module_usage={"foo": {"module": "foo", "import_locations": ["z.py"]}},
        )
        assert cg.import_map == {"y.py": ["bar"]}
