"""K3: the vulnerability search result must not advertise component fields no writer fills.

``details.purl`` and ``details.type`` are written by the license normalizer only; production
carries them on 0 of the vulnerability findings of every latest scan, so the search payload
shipped two permanently-null keys.
"""

from types import SimpleNamespace

from app.api.v1.endpoints.analytics.search import _vuln_results_for_finding


def _prod_shaped_vuln_finding():
    """An aggregated vulnerability document as the engine persists it: no purl, no type."""
    return SimpleNamespace(
        finding_id="spring-boot-starter-web:3.4.5",
        aliases=["CVE-2026-41852"],
        severity="CRITICAL",
        component="spring-boot-starter-web",
        version="3.4.5",
        project_id="proj-1",
        scan_id="scan-1",
        type="vulnerability",
        description="Spring Boot vulnerability",
        waived=False,
        waiver_reason=None,
        details={
            "epss_score": 0.00177,
            "risk_score": 40.0,
            "vulnerabilities": [
                {
                    "id": "GHSA-9f52-rjqv-25qv",
                    "resolved_cve": "CVE-2026-41852",
                    "severity": "CRITICAL",
                    "cvss_score": None,
                    "aliases": ["CVE-2026-41852"],
                    "scanners": ["osv"],
                }
            ],
        },
    )


def test_result_carries_no_permanently_null_component_fields():
    results = _vuln_results_for_finding(_prod_shaped_vuln_finding(), "cve-2026", None, None, {"proj-1": "demo"})
    assert len(results) == 1
    payload = results[0].model_dump()
    assert "purl" not in payload
    assert "component_type" not in payload
    assert payload["component"] == "spring-boot-starter-web"
