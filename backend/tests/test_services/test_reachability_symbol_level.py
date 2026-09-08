"""Symbol-level reachability end to end: OSV ecosystem_specific must survive
normalization and aggregation so the reachability engine can reach the symbol tier."""

from app.core.constants import REACHABILITY_HIGH_CONFIDENCE_THRESHOLD
from app.services.aggregation import ResultAggregator
from app.services.reachability_enrichment import _analyze_reachability, _prepare_callgraph


class _FakeCallgraph:
    def __init__(self, module_usage, language):
        self.module_usage = module_usage
        self.import_map = {}
        self.language = language
        self.analyzed_modules = list(module_usage)


def _go_osv_result():
    return {
        "osv_vulnerabilities": [
            {
                "component": "golang.org/x/net",
                "version": "0.16.0",
                "vulnerabilities": [
                    {
                        "id": "GO-2023-0001",
                        "summary": "HTTP/2 rapid reset",
                        "database_specific": {"severity": "HIGH"},
                        "affected": [
                            {
                                "ranges": [{"events": [{"fixed": "0.17.0"}]}],
                                "ecosystem_specific": {
                                    "imports": [
                                        {
                                            "path": "golang.org/x/net/http2",
                                            "symbols": ["Server.ServeConn", "ConfigureServer"],
                                        }
                                    ]
                                },
                            }
                        ],
                    }
                ],
            }
        ]
    }


def _aggregated_finding_dict():
    agg = ResultAggregator()
    agg.aggregate("osv", _go_osv_result())
    findings = agg.get_findings()
    assert len(findings) == 1
    return findings[0].model_dump()


def test_osv_ecosystem_specific_survives_into_stored_entry():
    finding = _aggregated_finding_dict()
    entry = finding["details"]["vulnerabilities"][0]
    assert entry["ecosystem_specific"]["imports"][0]["symbols"] == [
        "Server.ServeConn",
        "ConfigureServer",
    ]
    # Surfaced at the entry level only, not duplicated into the nested details copy.
    assert "ecosystem_specific" not in entry["details"]


def test_symbol_level_reachability_from_stored_shape():
    finding = _aggregated_finding_dict()
    module_usage = {
        "golang.org/x/net": {
            "import_locations": ["cmd/server/main.go"],
            "used_symbols": ["ConfigureServer"],
        }
    }
    result = _analyze_reachability(finding, "golang.org/x/net", _prepare_callgraph(_FakeCallgraph(module_usage, "go")))
    assert result["analysis_level"] == "symbol"
    assert result["is_reachable"] is True
    assert result["confidence_score"] >= REACHABILITY_HIGH_CONFIDENCE_THRESHOLD
    assert result["matched_symbols"] == ["ConfigureServer"]


def test_import_level_when_no_symbols_in_advisory():
    agg = ResultAggregator()
    payload = _go_osv_result()
    del payload["osv_vulnerabilities"][0]["vulnerabilities"][0]["affected"][0]["ecosystem_specific"]
    agg.aggregate("osv", payload)
    finding = agg.get_findings()[0].model_dump()
    module_usage = {"golang.org/x/net": {"import_locations": ["main.go"], "used_symbols": ["X"]}}
    result = _analyze_reachability(finding, "golang.org/x/net", _prepare_callgraph(_FakeCallgraph(module_usage, "go")))
    assert result["analysis_level"] == "import"
    assert result["confidence_score"] < REACHABILITY_HIGH_CONFIDENCE_THRESHOLD


_IMPORT_SITES = 40
_ADVISORY_SYMBOLS = 12
_MESSAGE_NAMES = 5


def _finding_with_symbols(count: int) -> dict:
    return {
        "type": "vulnerability",
        "component": "golang.org/x/net",
        "details": {
            "vulnerabilities": [
                {
                    "id": "GO-2023-0001",
                    "ecosystem_specific": {"symbols": [f"Sym{index:02d}" for index in range(count)]},
                }
            ]
        },
    }


def _analyzed(finding: dict, module_usage: dict) -> dict:
    prepared = _prepare_callgraph(_FakeCallgraph(module_usage, "go"))
    return dict(_analyze_reachability(finding, "golang.org/x/net", prepared))


def test_the_import_count_is_the_number_of_import_sites_not_the_sample_size():
    """The count was len(locations[:10]), so a package imported in 40 files reported 10."""
    module_usage = {
        "golang.org/x/net": {
            "import_locations": [f"cmd/mod{index}.go" for index in range(_IMPORT_SITES)],
            "used_symbols": [],
        }
    }

    result = _analyzed(_finding_with_symbols(0), module_usage)

    assert f"imported in {_IMPORT_SITES} file(s)" in result["message"]
    assert result["import_location_count"] == _IMPORT_SITES
    assert len(result["import_locations"]) < _IMPORT_SITES


def test_a_symbol_sentence_says_how_many_symbols_it_does_not_name():
    module_usage = {
        "golang.org/x/net": {
            "import_locations": ["main.go"],
            "used_symbols": [f"Sym{index:02d}" for index in range(_ADVISORY_SYMBOLS)],
        }
    }

    result = _analyzed(_finding_with_symbols(_ADVISORY_SYMBOLS), module_usage)

    assert f"and {_ADVISORY_SYMBOLS - _MESSAGE_NAMES} more" in result["message"]


def test_the_symbol_sample_is_ordered_so_two_runs_name_the_same_symbols():
    """get_symbols_for_finding unions through a set, so an unsorted sample is arbitrary."""
    module_usage = {"golang.org/x/net": {"import_locations": ["main.go"], "used_symbols": ["Other"]}}

    result = _analyzed(_finding_with_symbols(_ADVISORY_SYMBOLS), module_usage)

    assert result["vulnerable_symbols"] == sorted(result["vulnerable_symbols"])
    assert result["vulnerable_symbol_count"] == _ADVISORY_SYMBOLS
    assert len(result["vulnerable_symbols"]) < _ADVISORY_SYMBOLS
