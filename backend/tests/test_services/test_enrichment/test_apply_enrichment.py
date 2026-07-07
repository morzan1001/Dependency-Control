"""Tests for finding-level enrichment application (services/enrichment/service.py)."""

from app.schemas.enrichment import VulnerabilityEnrichment
from app.services.enrichment.service import _apply_enrichment_to_finding


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
