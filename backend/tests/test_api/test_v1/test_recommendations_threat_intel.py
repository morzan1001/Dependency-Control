"""The recommendations endpoint refreshes each finding's advisories with live KEV/EPSS before the
engine runs, so a CVE listed in KEV after the scan raises its card."""

import asyncio
from unittest.mock import patch

from app.api.v1.endpoints.analytics.recommendations import _apply_live_threat_intel
from app.schemas.enrichment import VulnerabilityEnrichment


def _live(cve: str, **fields) -> VulnerabilityEnrichment:
    return VulnerabilityEnrichment(cve=cve, risk_score=20.0, **fields)


MODULE = "app.api.v1.endpoints.analytics.recommendations"


def _finding(details: dict) -> dict:
    return {"type": "vulnerability", "component": "c", "version": "1", "details": details}


def _run(findings, enrichments):
    async def _fake(cves):
        return {c: enrichments[c] for c in cves if c in enrichments}

    with patch(f"{MODULE}.get_cve_enrichment", new=_fake):
        return asyncio.run(_apply_live_threat_intel(findings))


class TestApplyLiveThreatIntel:
    def test_kev_and_epss_written_from_canonical_cves(self):
        # advisory listed as GHSA + its CVE alias; enrichment keyed on the canonical CVE
        f = _finding({"vulnerabilities": [{"id": "GHSA-x", "aliases": ["CVE-1"]}]})
        _run([f], {"CVE-1": _live("CVE-1", is_kev=True, epss_score=0.9)})
        assert f["details"]["in_kev"] is True
        assert f["details"]["epss_score"] == 0.9
        assert f["details"]["vulnerabilities"][0]["in_kev"] is True

    def test_each_advisory_is_marked_and_the_finding_rolls_up_from_them(self):
        f = _finding(
            {
                "vulnerabilities": [
                    {"id": "CVE-1", "resolved_cve": "CVE-1"},
                    {"id": "CVE-2", "resolved_cve": "CVE-2"},
                ]
            }
        )
        _run(
            [f],
            {
                "CVE-1": _live("CVE-1", is_kev=False, epss_score=0.2, kev_ransomware_use=False),
                "CVE-2": _live("CVE-2", is_kev=True, epss_score=0.7, kev_ransomware_use=True),
            },
        )
        assert f["details"]["in_kev"] is True
        assert f["details"]["kev_ransomware_use"] is True
        assert f["details"]["epss_score"] == 0.7  # max across advisories
        first, second = f["details"]["vulnerabilities"]
        assert "in_kev" not in first
        assert second["kev_ransomware_use"] is True

    def test_live_epss_replaces_the_stored_value(self):
        f = _finding({"epss_score": 0.95, "vulnerabilities": [{"id": "CVE-1", "resolved_cve": "CVE-1"}]})
        _run([f], {"CVE-1": _live("CVE-1", epss_score=0.1)})
        assert f["details"]["epss_score"] == 0.1

    def test_non_vulnerability_findings_untouched(self):
        f = {"type": "secret", "details": {"vulnerabilities": [{"id": "CVE-1"}]}}
        _run([f], {"CVE-1": _live("CVE-1", is_kev=True)})
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

    def test_the_per_cve_enrichment_is_handed_back_for_the_cards(self):
        f = _finding({"vulnerabilities": [{"id": "CVE-1", "aliases": ["CVE-2"]}]})
        live = {"CVE-1": _live("CVE-1"), "CVE-2": _live("CVE-2", is_kev=True)}

        assert _run([f], live) == live

    def test_a_failed_refresh_hands_back_no_enrichment(self):
        f = _finding({"vulnerabilities": [{"id": "CVE-1"}]})

        async def _down(cves):
            raise RuntimeError("feed down")

        with patch(f"{MODULE}.get_cve_enrichment", new=_down):
            assert asyncio.run(_apply_live_threat_intel([f])) == {}
