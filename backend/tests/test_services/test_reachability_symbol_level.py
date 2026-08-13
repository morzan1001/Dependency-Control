"""Symbol-level reachability end to end: OSV ecosystem_specific must survive
normalization and aggregation so the reachability engine can reach the symbol tier."""

from app.core.constants import REACHABILITY_HIGH_CONFIDENCE_THRESHOLD
from app.services.aggregation import ResultAggregator
from app.services.reachability_enrichment import _analyze_reachability


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
    result = _analyze_reachability(finding, "golang.org/x/net", module_usage, {}, "go")
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
    result = _analyze_reachability(finding, "golang.org/x/net", module_usage, {}, "go")
    assert result["analysis_level"] == "import"
    assert result["confidence_score"] < REACHABILITY_HIGH_CONFIDENCE_THRESHOLD
