"""Advisories get live KEV/EPSS before the engine runs, so a CVE listed in KEV after the scan raises its card."""

import asyncio
from unittest.mock import patch

from app.api.v1.endpoints.analytics.recommendations import _apply_live_threat_intel
from app.models.finding import Finding, FindingType
from app.schemas.enrichment import VulnerabilityEnrichment
from app.schemas.recommendation import RecommendationType
from app.services.analysis.engine import _prepare_finding_records
from app.services.enrichment.scoring import calculate_risk_score
from app.services.recommendation.incidents import detect_known_exploits
from tests.helpers.findings import stored_vulnerability


def _live(cve: str, **fields) -> VulnerabilityEnrichment:
    return VulnerabilityEnrichment(cve=cve, risk_score=20.0, **fields)


MODULE = "app.api.v1.endpoints.analytics.recommendations"


def _finding(advisories: list[dict]) -> dict:
    finding = Finding.model_validate(stored_vulnerability("c", "1", advisories))
    [record], _ = _prepare_finding_records([finding], "s", "p", None)
    return record


def _refresh(findings, enrichments, unavailable=()):
    async def _fake(cves):
        return {c: enrichments[c] for c in cves if c in enrichments}, list(unavailable)

    with patch(f"{MODULE}.vulnerability_enrichment_service.enrich_cves", new=_fake):
        return asyncio.run(_apply_live_threat_intel(findings))


def _run(findings, enrichments):
    return _refresh(findings, enrichments)[0]


class TestApplyLiveThreatIntel:
    def test_kev_and_epss_written_from_canonical_cves(self):
        # advisory listed as GHSA + its CVE alias; enrichment keyed on the canonical CVE
        f = _finding([{"id": "GHSA-x", "aliases": ["CVE-1"]}])
        _run([f], {"CVE-1": _live("CVE-1", in_kev=True, epss_score=0.9)})
        [advisory] = f["details"]["vulnerabilities"]
        assert advisory["in_kev"] is True
        assert advisory["epss_score"] == 0.9

    def test_each_advisory_is_marked_from_its_own_cve(self):
        f = _finding([{"id": "CVE-1", "resolved_cve": "CVE-1"}, {"id": "CVE-2", "resolved_cve": "CVE-2"}])
        _run(
            [f],
            {
                "CVE-1": _live("CVE-1", in_kev=False, epss_score=0.2, kev_ransomware_use=False),
                "CVE-2": _live("CVE-2", in_kev=True, epss_score=0.7, kev_ransomware_use=True),
            },
        )
        first, second = sorted(f["details"]["vulnerabilities"], key=lambda a: a["id"])
        assert "in_kev" not in first
        assert first["epss_score"] == 0.2
        assert second["kev_ransomware_use"] is True
        assert second["epss_score"] == 0.7

    def test_live_epss_replaces_the_stored_value(self):
        f = _finding([{"id": "CVE-1", "resolved_cve": "CVE-1", "epss_score": 0.95}])
        _run([f], {"CVE-1": _live("CVE-1", epss_score=0.1)})
        assert f["details"]["vulnerabilities"][0]["epss_score"] == 0.1

    def test_non_vulnerability_findings_untouched(self):
        f = _finding([{"id": "CVE-1"}]) | {"type": FindingType.SECRET.value}
        _run([f], {"CVE-1": _live("CVE-1", in_kev=True)})
        assert "in_kev" not in f["details"]["vulnerabilities"][0]

    def test_no_cves_no_enrichment_call(self):
        f = _finding([{"id": "CVE-1", "waived": True}])
        called = {"n": 0}

        async def _fake(cves):
            called["n"] += 1
            return {}, []

        with patch(f"{MODULE}.vulnerability_enrichment_service.enrich_cves", new=_fake):
            asyncio.run(_apply_live_threat_intel([f]))
        assert called["n"] == 0, "must not call enrichment when there are no CVEs"

    def test_the_per_cve_enrichment_is_handed_back_for_the_cards(self):
        f = _finding([{"id": "CVE-1", "aliases": ["CVE-2"]}])
        live = {"CVE-1": _live("CVE-1"), "CVE-2": _live("CVE-2", in_kev=True)}

        assert _run([f], live) == live

    def test_a_failed_refresh_hands_back_no_enrichment_and_names_both_sources(self):
        f = _finding([{"id": "CVE-1"}])

        async def _down(cves):
            raise RuntimeError("feed down")

        with patch(f"{MODULE}.vulnerability_enrichment_service.enrich_cves", new=_down):
            assert asyncio.run(_apply_live_threat_intel([f])) == ({}, ["KEV", "EPSS"])

    def test_a_complete_refresh_names_no_unavailable_source(self):
        f = _finding([{"id": "CVE-1", "resolved_cve": "CVE-1"}])
        assert _refresh([f], {"CVE-1": _live("CVE-1", epss_score=0.1)})[1] == []

    def test_a_kev_outage_keeps_the_stored_marks_and_scores(self):
        stored = {"in_kev": True, "kev_ransomware_use": True, "epss_score": 0.4, "risk_score": 88.0}
        f = _finding([{"id": "CVE-1", "resolved_cve": "CVE-1", **stored}])

        enrichments, unavailable = _refresh([f], {"CVE-1": _live("CVE-1", epss_score=0.9)}, ["KEV"])

        assert (enrichments, unavailable) == ({}, ["KEV"])
        [advisory] = f["details"]["vulnerabilities"]
        assert {key: advisory.get(key) for key in stored} == stored

    def test_a_kev_outage_keeps_the_ransomware_card_of_a_bundled_advisory(self):
        f = _finding([{"id": "CVE-1", "aliases": ["CVE-2"], "in_kev": True, "kev_ransomware_use": True}])
        live = {"CVE-1": _live("CVE-1"), "CVE-2": _live("CVE-2")}

        enrichments, _ = _refresh([f], live, ["KEV"])

        assert RecommendationType.RANSOMWARE_RISK in {r.type for r in detect_known_exploits([f], enrichments)}

    def test_an_epss_outage_still_raises_a_cve_newly_in_kev_and_keeps_its_stored_epss(self):
        stored = {"epss_score": 0.42, "epss_percentile": 97.0, "epss_date": "2026-10-01"}
        f = _finding([{"id": "CVE-1", "resolved_cve": "CVE-1", "cvss_score": 7.5, **stored}])

        enrichments, unavailable = _refresh([f], {"CVE-1": _live("CVE-1", in_kev=True)}, ["EPSS"])

        assert unavailable == ["EPSS"]
        [advisory] = f["details"]["vulnerabilities"]
        assert (advisory["in_kev"], {key: advisory[key] for key in stored}) == (True, stored)
        assert advisory["risk_score"] == calculate_risk_score(7.5, 0.42, True, False)
        assert RecommendationType.KNOWN_EXPLOIT in {r.type for r in detect_known_exploits([f], enrichments)}

    def test_an_epss_outage_counts_only_the_kev_cve_of_a_bundled_advisory(self):
        f = _finding([{"id": "CVE-2024-0001", "aliases": ["CVE-2024-0002"]}])
        live = {"CVE-2024-0001": _live("CVE-2024-0001", in_kev=True), "CVE-2024-0002": _live("CVE-2024-0002")}

        enrichments, _ = _refresh([f], live, ["EPSS"])

        [card] = [r for r in detect_known_exploits([f], enrichments) if r.type == RecommendationType.KNOWN_EXPLOIT]
        assert (card.impact["kev_count"], card.action["cves"]) == (1, ["CVE-2024-0001"])

    def test_an_epss_outage_leaves_an_advisory_outside_kev_as_stored(self):
        stored = {"epss_score": 0.42, "risk_score": 55.0}
        f = _finding([{"id": "CVE-1", "resolved_cve": "CVE-1", **stored}])

        _refresh([f], {"CVE-1": _live("CVE-1")}, ["EPSS"])

        [advisory] = f["details"]["vulnerabilities"]
        assert ("in_kev" in advisory, {key: advisory[key] for key in stored}) == (False, stored)


class TestRefreshedCards:
    def test_a_cve_listed_after_the_scan_leaves_the_epss_card_for_the_ransomware_card(self):
        f = _finding([{"id": "CVE-2021-44228", "epss_score": 0.8}])
        live = _run([f], {"CVE-2021-44228": _live("CVE-2021-44228", in_kev=True, kev_ransomware_use=True)})

        cards = {r.type for r in detect_known_exploits([f], live)}

        assert RecommendationType.RANSOMWARE_RISK in cards
        assert RecommendationType.ACTIVELY_EXPLOITED not in cards

    def test_a_waived_advisory_is_not_refreshed(self):
        f = _finding([{"id": "CVE-1", "waived": True}, {"id": "CVE-2"}])
        requested: list[str] = []

        async def _fake(cves):
            requested.extend(cves)
            return {}, []

        with patch(f"{MODULE}.vulnerability_enrichment_service.enrich_cves", new=_fake):
            asyncio.run(_apply_live_threat_intel([f]))

        assert requested == ["CVE-2"]
