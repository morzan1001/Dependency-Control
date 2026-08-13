"""Tests for finding-level enrichment application."""

import pytest

from app.schemas.enrichment import GHSAData, VulnerabilityEnrichment
from app.services.enrichment.service import (
    VulnerabilityEnrichmentService,
    _apply_enrichment_to_finding,
    _apply_ghsa_resolutions,
)


def test_kev_ransomware_use_aggregates_monotonically():
    """A later non-ransomware KEV CVE must not clobber the ransomware flag to False."""
    finding: dict = {"details": {"vulnerabilities": []}}
    ransomware = VulnerabilityEnrichment(cve="CVE-1", is_kev=True, kev_ransomware_use=True)
    benign_kev = VulnerabilityEnrichment(cve="CVE-2", is_kev=True, kev_ransomware_use=False)

    _apply_enrichment_to_finding(finding, ransomware)
    _apply_enrichment_to_finding(finding, benign_kev)

    assert finding["details"]["kev_ransomware_use"] is True
    assert finding["details"]["in_kev"] is True


def test_ghsa_resolution_propagates_cvss_to_resolved_cve():
    """CVSS under a GHSA id must carry to the resolved CVE key so risk scoring uses the real CVSS."""
    finding = {
        "_id": "f1",
        "details": {"vulnerabilities": [{"id": "GHSA-xxxx", "cvss_score": 9.8}]},
    }
    cve_to_findings = {"GHSA-xxxx": [finding]}
    cvss_scores = {"GHSA-xxxx": 9.8}
    ghsa_resolutions = {"GHSA-xxxx": GHSAData(ghsa_id="GHSA-xxxx", cve_id="CVE-2024-1234")}

    _apply_ghsa_resolutions(ghsa_resolutions, cve_to_findings, cvss_scores)

    assert cvss_scores["CVE-2024-1234"] == 9.8


def test_ghsa_resolution_does_not_clobber_existing_cve_cvss():
    finding = {"_id": "f1", "details": {"vulnerabilities": [{"id": "GHSA-yyyy"}]}}
    cve_to_findings = {"GHSA-yyyy": [finding]}
    cvss_scores = {"GHSA-yyyy": 4.0, "CVE-2024-9999": 7.5}
    ghsa_resolutions = {"GHSA-yyyy": GHSAData(ghsa_id="GHSA-yyyy", cve_id="CVE-2024-9999")}

    _apply_ghsa_resolutions(ghsa_resolutions, cve_to_findings, cvss_scores)

    assert cvss_scores["CVE-2024-9999"] == 7.5


@pytest.mark.asyncio
async def test_ghsa_resolution_collapses_cve_and_ghsa_entries(monkeypatch):
    """Entries stored separately per scanner must fold into one once GHSA->CVE links them (C10)."""
    service = VulnerabilityEnrichmentService()
    finding = {
        "_id": "f1",
        "details": {
            "vulnerabilities": [
                {
                    "id": "CVE-2026-59888",
                    "severity": "HIGH",
                    "aliases": [],
                    "scanners": ["trivy"],
                    "fixed_version": "2.18.8, 2.21.4",
                    "cvss_score": 7.5,
                    "references": [],
                },
                {
                    "id": "GHSA-3pjw-73gf-8qr5",
                    "severity": "HIGH",
                    "aliases": [],
                    "scanners": ["grype"],
                    "fixed_version": "2.21.4",
                    "cvss_score": 7.7,
                    "references": [],
                },
            ],
            "fixed_version": "2.21.4",
        },
    }

    async def fake_resolve(ghsa_ids):
        return {"GHSA-3pjw-73gf-8qr5": GHSAData(ghsa_id="GHSA-3pjw-73gf-8qr5", cve_id="CVE-2026-59888")}

    async def fake_enrich_cves(cves, cvss_scores=None):
        return {}

    monkeypatch.setattr(service, "resolve_ghsa_to_cve", fake_resolve)
    monkeypatch.setattr(service, "enrich_cves", fake_enrich_cves)

    await service.enrich_findings([finding])

    vulns = finding["details"]["vulnerabilities"]
    assert len(vulns) == 1
    merged = vulns[0]
    assert merged["id"] == "CVE-2026-59888"
    assert "GHSA-3pjw-73gf-8qr5" in merged["aliases"]
    assert merged["resolved_cve"] == "CVE-2026-59888"
    assert set(merged["scanners"]) == {"trivy", "grype"}
    assert merged["fixed_version"] == "2.18.8, 2.21.4"
    assert merged["cvss_score"] == 7.7
