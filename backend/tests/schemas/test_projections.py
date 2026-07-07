"""Tests for database projection schemas (app.schemas.projections)."""

from app.schemas.projections import CallgraphMinimal


class TestCallgraphMinimalImportMap:
    """CallgraphMinimal.import_map is derived from the persisted imports list.

    The callgraph writer stores a raw ``imports`` list (List[ImportEntry]) but
    never an ``import_map`` key, so the previously phantom ``import_map`` field
    was always empty/None. It must be derived as {file: [modules]} so
    reachability's import fallback and the total_imports stat see real data.
    """

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
        # Must never be None: build_reachability_summary does
        # len(cg.get("import_map", {})) on model_dump output, which raises
        # TypeError if import_map serializes to None.
        cg = CallgraphMinimal(_id="cg-1", language="javascript")
        assert cg.import_map == {}
        assert cg.model_dump(by_alias=True)["import_map"] == {}

    def test_explicit_import_map_is_preserved(self):
        # If a document ever supplies import_map directly, honor it and do not
        # overwrite it with a derivation.
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
    """import_map derives from module_usage under the ACTUAL minimal projection.

    The minimal DB projection (repositories/callgraphs.py) is
    ``{_id, module_usage, import_map, language}`` -- it projects the phantom
    ``import_map`` (absent in Mongo) and the aggregated ``module_usage`` but NOT
    the raw ``imports`` list. So in production ``imports`` is always [] and the
    fallback/total_imports would be dead UNLESS import_map is derived from
    module_usage. These tests exercise that production shape end-to-end.
    """

    def _minimal_projection_doc(self):
        # Mirrors what Mongo returns for _MINIMAL_PROJECTION: module_usage is a
        # dict keyed by module name, values are serialized ModuleUsage dicts;
        # NO raw imports list is present.
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
        # build_reachability_summary computes len(cg.get("import_map", {})) over
        # model_dump output. Prove it is non-zero (== number of importing files)
        # for a realistic minimal-projection doc, i.e. the stat is no longer dead.
        cg = CallgraphMinimal(**self._minimal_projection_doc())
        dumped = cg.model_dump(by_alias=True)
        assert len(dumped["import_map"]) == 2

    def test_reachability_fallback_sees_package_via_derived_map(self):
        # _check_package_in_imports iterates import_map.items() -> {file: [mods]}.
        # The derived map must let it find a package by module name.
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
        # When a full document is loaded (raw imports present), that richer
        # source wins over the module_usage fallback.
        cg = CallgraphMinimal(
            _id="cg-1",
            imports=[{"module": "bar", "file": "y.py", "line": 1}],
            module_usage={"foo": {"module": "foo", "import_locations": ["z.py"]}},
        )
        assert cg.import_map == {"y.py": ["bar"]}
