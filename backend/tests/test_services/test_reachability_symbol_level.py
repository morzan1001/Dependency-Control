"""Symbol-level reachability end to end: OSV ecosystem_specific must survive
normalization and aggregation so the reachability engine can reach the symbol tier."""

from app.api.v1.helpers.callgraph import parse_generic_format
from app.core.constants import REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO, REACHABILITY_HIGH_CONFIDENCE_THRESHOLD
from app.schemas.projections import CallgraphMinimal
from app.services.aggregation import ResultAggregator
from app.services.analysis.stats import compute_stats
from app.services.reachability_enrichment import enrich_findings_with_reachability, is_high_confidence_reachable


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
                        "fixed_version": "0.17.0",
                        "ecosystem_specific": {
                            "imports": [
                                {"path": "golang.org/x/net/http2", "symbols": ["Server.ServeConn", "ConfigureServer"]}
                            ]
                        },
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


def _enriched(finding: dict, module_usage: dict) -> dict:
    callgraph = CallgraphMinimal(
        _id="cg-go", language="go", module_usage=module_usage, analyzed_modules=list(module_usage)
    )
    enrich_findings_with_reachability([finding], [callgraph], {})
    return finding["details"]["reachability"]


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
    result = _enriched(finding, module_usage)
    assert result["analysis_level"] == "symbol"
    assert result["is_reachable"] is True
    assert result["confidence_score"] >= REACHABILITY_HIGH_CONFIDENCE_THRESHOLD
    assert result["matched_symbols"] == ["ConfigureServer"]


def test_import_level_when_no_symbols_in_advisory():
    agg = ResultAggregator()
    payload = _go_osv_result()
    del payload["osv_vulnerabilities"][0]["vulnerabilities"][0]["ecosystem_specific"]
    agg.aggregate("osv", payload)
    finding = agg.get_findings()[0].model_dump()
    module_usage = {"golang.org/x/net": {"import_locations": ["main.go"], "used_symbols": ["X"]}}
    result = _enriched(finding, module_usage)
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


def test_the_import_count_is_the_number_of_import_sites_not_the_sample_size():
    """The count was len(locations[:10]), so a package imported in 40 files reported 10."""
    module_usage = {
        "golang.org/x/net": {
            "import_locations": [f"cmd/mod{index}.go" for index in range(_IMPORT_SITES)],
            "used_symbols": [],
        }
    }

    result = _enriched(_finding_with_symbols(0), module_usage)

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

    result = _enriched(_finding_with_symbols(_ADVISORY_SYMBOLS), module_usage)

    assert f"and {_ADVISORY_SYMBOLS - _MESSAGE_NAMES} more" in result["message"]


def test_the_symbol_sample_is_ordered_so_two_runs_name_the_same_symbols():
    """get_symbols_for_finding unions through a set, so an unsorted sample is arbitrary."""
    module_usage = {"golang.org/x/net": {"import_locations": ["main.go"], "used_symbols": ["Other"]}}

    result = _enriched(_finding_with_symbols(_ADVISORY_SYMBOLS), module_usage)

    assert result["vulnerable_symbols"] == sorted(result["vulnerable_symbols"])
    assert result["vulnerable_symbol_count"] == _ADVISORY_SYMBOLS
    assert len(result["vulnerable_symbols"]) < _ADVISORY_SYMBOLS


def test_symbols_searched_and_not_used_rank_below_every_import_verdict():
    finding = _aggregated_finding_dict()
    parsed = parse_generic_format(
        {"imports": [{"module": "golang.org/x/net", "file": "cmd/server", "line": 0, "symbols": ["Transport"]}]},
        "go",
    )

    reach = _enriched(finding, {key: usage.model_dump() for key, usage in parsed.module_usage.items()})

    assert reach["analysis_level"] == "import"
    assert reach["confidence_score"] < REACHABILITY_CONFIDENCE_NO_SYMBOL_INFO
    assert not is_high_confidence_reachable(reach["is_reachable"], reach["confidence_score"])
    assert compute_stats([finding], {}).reachability.reachable_count_high_confidence == 0


def test_a_stored_call_only_usage_is_worded_from_its_call_edges():
    module = "github.com/sirupsen/logrus"
    stored = {
        module: {"module": module, "import_count": 0, "call_count": 3, "import_locations": [], "used_symbols": ["Info"]}
    }

    reach = _enriched({"type": "vulnerability", "component": module, "details": {}}, stored)

    assert reach["is_reachable"] is True
    assert "3 call edge(s)" in reach["message"]
    assert "0 file(s)" not in reach["message"]
