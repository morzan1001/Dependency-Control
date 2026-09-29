"""The per-advisory enrichment fold and how it lands on a finding's advisories."""

import itertools

import pytest
from pydantic import ValidationError

from app.core.constants import EXPLOIT_MATURITY_ORDER
from app.core.risk_scoring import calculate_exploit_maturity
from app.schemas.enrichment import GHSAData, VulnerabilityEnrichment
from app.services.enrichment.scoring import fold_enrichments
from app.services.enrichment.service import VulnerabilityEnrichmentService, apply_enrichments


def _enrichment(cve: str, **fields) -> VulnerabilityEnrichment:
    return VulnerabilityEnrichment(cve=cve, risk_score=fields.pop("risk_score", 20.0), **fields)


def _folded(*enrichments: VulnerabilityEnrichment) -> list[VulnerabilityEnrichment | None]:
    return [fold_enrichments(order) for order in itertools.permutations(enrichments)]


def test_the_fold_keeps_the_worst_case_whatever_the_order():
    folds = _folded(
        _enrichment("CVE-1", epss_score=0.2, epss_percentile=40.0, risk_score=91.0, exploit_maturity="medium"),
        _enrichment(
            "CVE-2",
            is_kev=True,
            kev_due_date="2025-06-01",
            kev_date_added="2025-01-02",
            kev_required_action="patch 2",
            kev_ransomware_use=True,
            exploit_maturity="weaponized",
        ),
        _enrichment(
            "CVE-3",
            epss_score=0.7,
            epss_percentile=97.0,
            is_kev=True,
            kev_due_date="2022-01-01",
            kev_date_added="2021-11-03",
            kev_required_action="patch 3",
            risk_score=12.0,
        ),
    )
    assert all(fold == folds[0] for fold in folds)
    fold = folds[0]
    assert fold is not None
    assert (fold.epss_score, fold.epss_percentile) == (0.7, 97.0)
    assert (fold.kev_due_date, fold.kev_date_added, fold.kev_required_action) == ("2022-01-01", "2021-11-03", "patch 3")
    assert fold.kev_ransomware_use is True
    assert fold.exploit_maturity == "weaponized"
    assert fold.risk_score == 91.0


def test_a_kev_entry_without_a_due_date_yields_to_one_with_a_deadline():
    [first, *rest] = _folded(
        _enrichment("CVE-1", is_kev=True, kev_required_action="no deadline"),
        _enrichment("CVE-2", is_kev=True, kev_due_date="2026-01-01", kev_required_action="deadline"),
    )
    assert all(fold == first for fold in rest)
    assert first is not None
    assert first.kev_required_action == "deadline"


def test_nothing_to_fold_is_none():
    assert fold_enrichments([]) is None


def test_an_enrichment_always_carries_its_risk_score():
    with pytest.raises(ValidationError):
        VulnerabilityEnrichment(cve="CVE-1")


def test_the_maturity_order_names_exactly_the_levels_scoring_produces():
    produced = {
        calculate_exploit_maturity(kev, ransomware, epss)
        for kev, ransomware, epss in itertools.product([False, True], [False, True], [None, 0.001, 0.05, 0.9])
    }
    assert set(EXPLOIT_MATURITY_ORDER) == produced


def test_enrichment_reaches_the_entry_the_cve_names_and_no_other():
    """A scanner may have filed the CVE under a GHSA id; EPSS and KEV belong on whichever entry
    carries the CVE, on that one alone."""
    details: dict = {
        "vulnerabilities": [
            {"id": "CVE-1"},
            {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-1"]},
            {"id": "CVE-2"},
        ]
    }
    apply_enrichments(
        details,
        {"CVE-1": _enrichment("CVE-1", epss_score=0.42, epss_percentile=97.0, is_kev=True, kev_due_date="2026-01-01")},
    )

    by_id = {vuln["id"]: vuln for vuln in details["vulnerabilities"]}
    assert by_id["CVE-1"]["epss_score"] == 0.42
    assert by_id["CVE-1"]["in_kev"] is True
    assert by_id["GHSA-aaaa-bbbb-cccc"]["epss_score"] == 0.42
    assert by_id["GHSA-aaaa-bbbb-cccc"]["in_kev"] is True
    assert "epss_score" not in by_id["CVE-2"]
    assert "in_kev" not in by_id["CVE-2"]
    assert details["in_kev"] is True


def test_a_resolved_ghsa_scores_its_cve_on_the_advisorys_cvss():
    details: dict = {"vulnerabilities": [{"id": "GHSA-xxxx", "resolved_cve": "CVE-2024-1234", "cvss_score": 9.8}]}
    apply_enrichments(details, {"CVE-2024-1234": _enrichment("CVE-2024-1234", is_kev=True)})
    assert details["risk_score"] == pytest.approx(59.2)


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

    async def fake_enrich_cves(cves):
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
    # Recomputed from the merged entry: the duplicate pair no longer forces 2.21.4 as covers-all fix.
    assert finding["details"]["fixed_version"] == "2.18.8"


def test_an_unenriched_negligible_advisory_ranks_below_a_low_one():
    details = {
        "vulnerabilities": [
            {"id": "GHSA-negl-igib-le00", "severity": "NEGLIGIBLE"},
            {"id": "GHSA-lowl-owlo-wlow", "severity": "LOW"},
        ]
    }

    apply_enrichments(details, {})

    negligible, low = details["vulnerabilities"]
    assert negligible["risk_score"] < low["risk_score"]
