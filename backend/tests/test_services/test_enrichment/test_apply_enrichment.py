"""Tests for finding-level enrichment application (services/enrichment/service.py)."""

from app.schemas.enrichment import GHSAData, VulnerabilityEnrichment
from app.services.enrichment.service import (
    _apply_enrichment_to_finding,
    _apply_ghsa_resolutions,
)


def test_kev_ransomware_use_aggregates_monotonically():
    """A finding with both a ransomware-linked and a non-ransomware KEV CVE must
    stay flagged — the non-ransomware CVE applied last must not clobber it to
    False (audit SC#3)."""
    finding: dict = {"details": {"vulnerabilities": []}}
    ransomware = VulnerabilityEnrichment(cve="CVE-1", is_kev=True, kev_ransomware_use=True)
    benign_kev = VulnerabilityEnrichment(cve="CVE-2", is_kev=True, kev_ransomware_use=False)

    _apply_enrichment_to_finding(finding, ransomware)
    _apply_enrichment_to_finding(finding, benign_kev)

    assert finding["details"]["kev_ransomware_use"] is True
    assert finding["details"]["in_kev"] is True


def test_ghsa_resolution_propagates_cvss_to_resolved_cve():
    """CVSS recorded under a GHSA id must be carried to the resolved CVE key so
    Phase 3 risk scoring uses the real CVSS instead of the neutral base
    (audit finding #1)."""
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
    """If the resolved CVE already has a CVSS score, the GHSA-derived score must
    not overwrite it."""
    finding = {"_id": "f1", "details": {"vulnerabilities": [{"id": "GHSA-yyyy"}]}}
    cve_to_findings = {"GHSA-yyyy": [finding]}
    cvss_scores = {"GHSA-yyyy": 4.0, "CVE-2024-9999": 7.5}
    ghsa_resolutions = {"GHSA-yyyy": GHSAData(ghsa_id="GHSA-yyyy", cve_id="CVE-2024-9999")}

    _apply_ghsa_resolutions(ghsa_resolutions, cve_to_findings, cvss_scores)

    assert cvss_scores["CVE-2024-9999"] == 7.5
