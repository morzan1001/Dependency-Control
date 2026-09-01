"""The recommendations endpoint enriches findings' details with live KEV/EPSS before the engine
runs, because ingest rarely writes KEV to findings (in_kev is set on ~0.2%)."""

import asyncio
from unittest.mock import patch

from app.api.v1.endpoints.analytics.recommendations import _apply_live_threat_intel
from app.schemas.enrichment import VulnerabilityEnrichment

MODULE = "app.api.v1.endpoints.analytics.recommendations"


def _finding(details: dict) -> dict:
    return {"type": "vulnerability", "component": "c", "version": "1", "details": details}


def _run(findings, enrichments):
    async def _fake(cves):
        return {c: enrichments[c] for c in cves if c in enrichments}

    with patch(f"{MODULE}.get_cve_enrichment", new=_fake):
        asyncio.run(_apply_live_threat_intel(findings))


class TestApplyLiveThreatIntel:
    def test_kev_and_epss_written_from_canonical_cves(self):
        # advisory listed as GHSA + its CVE alias; enrichment keyed on the canonical CVE
        f = _finding({"vulnerabilities": [{"id": "GHSA-x", "aliases": ["CVE-1"]}]})
        _run([f], {"CVE-1": VulnerabilityEnrichment(cve="CVE-1", is_kev=True, epss_score=0.9)})
        assert f["details"]["in_kev"] is True
        assert f["details"]["epss_score"] == 0.9

    def test_finding_level_worst_case_across_advisories(self):
        f = _finding({"vulnerabilities": [
            {"id": "CVE-1", "resolved_cve": "CVE-1"},
            {"id": "CVE-2", "resolved_cve": "CVE-2"},
        ]})
        _run([f], {
            "CVE-1": VulnerabilityEnrichment(cve="CVE-1", is_kev=False, epss_score=0.2, kev_ransomware_use=False),
            "CVE-2": VulnerabilityEnrichment(cve="CVE-2", is_kev=True, epss_score=0.7, kev_ransomware_use=True),
        })
        assert f["details"]["in_kev"] is True
        assert f["details"]["kev_ransomware_use"] is True
        assert f["details"]["epss_score"] == 0.7  # max across advisories

    def test_does_not_lower_existing_epss(self):
        f = _finding({"epss_score": 0.95, "vulnerabilities": [{"id": "CVE-1", "resolved_cve": "CVE-1"}]})
        _run([f], {"CVE-1": VulnerabilityEnrichment(cve="CVE-1", epss_score=0.1)})
        assert f["details"]["epss_score"] == 0.95

    def test_non_vulnerability_findings_untouched(self):
        f = {"type": "secret", "details": {"vulnerabilities": [{"id": "CVE-1"}]}}
        _run([f], {"CVE-1": VulnerabilityEnrichment(cve="CVE-1", is_kev=True)})
        assert "in_kev" not in f["details"]

    def test_no_cves_no_enrichment_call(self):
        f = _finding({"vulnerabilities": []})
        called = {"n": 0}

        async def _fake(cves):
            called["n"] += 1
            return {}

        with patch(f"{MODULE}.get_cve_enrichment", new=_fake):
            asyncio.run(_apply_live_threat_intel([f]))
        assert called["n"] == 0, "must not call enrichment when there are no CVEs"
