"""enrich_findings marks each advisory with its own CVEs and rolls the finding up from them,
whatever order the CVEs, findings or providers come in."""

import itertools

import pytest

from app.schemas.enrichment import EPSSData, GHSAData, KEVEntry
from app.schemas.finding_details import VulnerabilityDetails, VulnerabilityEntryDetails
from app.services.enrichment.service import VulnerabilityEnrichmentService


def _kev(cve: str, due: str, *, ransomware: bool = False) -> KEVEntry:
    return KEVEntry(
        cve=cve,
        vendor_project="v",
        product="p",
        vulnerability_name="n",
        date_added=f"added-{cve}",
        short_description="d",
        required_action=f"action-{cve}",
        due_date=due,
        known_ransomware_use=ransomware,
    )


def _epss(cve: str, score: float) -> EPSSData:
    return EPSSData(cve=cve, epss_score=score, percentile=score * 100, date="2026-09-01")


def _service(monkeypatch, kev=(), epss=(), ghsa=()) -> VulnerabilityEnrichmentService:
    service = VulnerabilityEnrichmentService()
    kev_catalog = {k.cve: k for k in kev}
    epss_scores = {e.cve: e for e in epss}
    resolutions = {g.ghsa_id: g for g in ghsa}

    async def client():
        return None

    async def load_kev(_client):
        return kev_catalog

    async def load_epss(_client, cves):
        return {c: epss_scores[c] for c in cves if c in epss_scores}

    async def resolve(ghsa_ids):
        return {g: resolutions[g] for g in ghsa_ids if g in resolutions}

    monkeypatch.setattr(service, "_get_client", client)
    monkeypatch.setattr(service._kev_provider, "load_kev_catalog", load_kev)
    monkeypatch.setattr(service._epss_provider, "load_epss_scores", load_epss)
    monkeypatch.setattr(service, "resolve_ghsa_to_cve", resolve)
    return service


def _vuln_finding(component: str, *entries: dict) -> dict:
    """An ad-hoc record: model_dump() plus finding_id, so no persistence _id."""
    return {
        "id": f"{component}:1.0",
        "finding_id": f"{component}:1.0",
        "type": "vulnerability",
        "component": component,
        "version": "1.0",
        "aliases": [],
        "details": {"vulnerabilities": [dict(entry) for entry in entries]},
    }


@pytest.mark.asyncio
async def test_every_finding_sharing_a_cve_is_enriched(monkeypatch):
    service = _service(
        monkeypatch,
        kev=[_kev("CVE-2021-23337", "2022-01-01"), _kev("CVE-2020-8203", "2022-02-01")],
        epss=[_epss("CVE-2021-23337", 0.9), _epss("CVE-2020-8203", 0.5)],
        ghsa=[GHSAData(ghsa_id="GHSA-p6mc-m468-83gw", cve_id="CVE-2020-8203")],
    )
    findings = [
        _vuln_finding("lodash", {"id": "CVE-2021-23337"}),
        _vuln_finding("lodash-es", {"id": "CVE-2021-23337"}),
        _vuln_finding("lodash.merge", {"id": "GHSA-p6mc-m468-83gw"}),
        _vuln_finding("lodash.set", {"id": "GHSA-p6mc-m468-83gw"}),
    ]

    await service.enrich_findings(findings)

    for finding in findings:
        details = finding["details"]
        assert details["in_kev"] is True, finding["component"]
        assert details["epss_score"] is not None, finding["component"]
        assert details["risk_score"] is not None, finding["component"]
    assert [f["details"]["vulnerabilities"][0].get("resolved_cve") for f in findings[2:]] == ["CVE-2020-8203"] * 2


@pytest.mark.asyncio
async def test_the_kev_deadline_is_the_earliest_with_its_own_action(monkeypatch):
    dues = ["2025-04-01", "2025-02-01", "2025-07-01", "2025-01-01", "2025-05-01", "2025-03-01", "2025-06-01"]
    kev = [_kev(f"CVE-2024-{n:04d}", due) for n, due in enumerate(dues)]
    service = _service(monkeypatch, kev=kev)
    finding = _vuln_finding("openssl", *({"id": k.cve} for k in kev))

    await service.enrich_findings([finding])

    details = finding["details"]
    assert details["kev_due_date"] == "2025-01-01"
    assert details["kev_required_action"] == "action-CVE-2024-0003"
    assert details["kev_date_added"] == "added-CVE-2024-0003"
    by_id = {entry["id"]: entry for entry in details["vulnerabilities"]}
    assert by_id["CVE-2024-0002"]["kev_due_date"] == "2025-07-01"
    assert by_id["CVE-2024-0002"]["kev_required_action"] == "action-CVE-2024-0002"
    assert by_id["CVE-2024-0002"]["kev_date_added"] == "added-CVE-2024-0002"


@pytest.mark.asyncio
async def test_an_advisory_keeps_the_highest_epss_among_its_cves(monkeypatch):
    aliases = [f"CVE-2024-{n:04d}" for n in range(1, 8)]
    service = _service(monkeypatch, epss=[_epss("CVE-2024-0000", 0.9), *(_epss(a, 0.001) for a in aliases)])
    finding = _vuln_finding("kernel", {"id": "CVE-2024-0000", "aliases": aliases})

    await service.enrich_findings([finding])

    [entry] = finding["details"]["vulnerabilities"]
    assert entry["epss_score"] == 0.9
    assert entry["epss_percentile"] == 90.0


@pytest.mark.asyncio
async def test_a_bundled_kev_cve_is_scored_with_its_advisorys_cvss(monkeypatch):
    service = _service(monkeypatch, kev=[_kev("CVE-2023-0002", "2024-01-01")])
    as_id = _vuln_finding("a", {"id": "CVE-2023-0002", "cvss_score": 9.8})
    as_alias = _vuln_finding("b", {"id": "CVE-2023-0001", "aliases": ["CVE-2023-0002"], "cvss_score": 9.8})

    await service.enrich_findings([as_id, as_alias])

    assert as_id["details"]["risk_score"] == pytest.approx(59.2)
    assert as_alias["details"]["risk_score"] == pytest.approx(59.2)


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse", [False, True])
async def test_each_finding_scores_a_shared_cve_on_its_own_cvss(monkeypatch, reverse):
    service = _service(monkeypatch)
    low = _vuln_finding("low", {"id": "CVE-2024-2", "cvss_score": 5.0})
    high = _vuln_finding("high", {"id": "CVE-2024-2", "cvss_score": 10.0})
    findings = [high, low] if reverse else [low, high]

    await service.enrich_findings(findings)

    assert low["details"]["risk_score"] == pytest.approx(20.0)
    assert high["details"]["risk_score"] == pytest.approx(40.0)


@pytest.mark.asyncio
async def test_an_advisory_without_a_cve_is_ranked_by_its_cvss(monkeypatch):
    service = _service(monkeypatch)
    finding = _vuln_finding("crate", {"id": "GHSA-aaaa-bbbb-cccc", "cvss_score": 9.8})

    await service.enrich_findings([finding])

    assert finding["details"]["risk_score"] == pytest.approx(39.2)


@pytest.mark.asyncio
async def test_an_advisory_without_a_cve_or_cvss_is_ranked_by_its_severity(monkeypatch):
    service = _service(monkeypatch)
    finding = _vuln_finding(
        "crate",
        {"id": "RUSTSEC-2024-0001", "severity": "CRITICAL"},
        {"id": "CVE-2024-3", "severity": "LOW", "cvss_score": 2.0},
    )

    await service.enrich_findings([finding])

    assert finding["details"]["risk_score"] == pytest.approx(40.0)


@pytest.mark.asyncio
async def test_the_advisory_url_stays_on_its_own_advisory(monkeypatch):
    service = _service(
        monkeypatch,
        ghsa=[
            GHSAData(ghsa_id="GHSA-aaaa-aaaa-aaaa", github_url="https://github.com/advisories/GHSA-aaaa-aaaa-aaaa"),
            GHSAData(ghsa_id="GHSA-bbbb-bbbb-bbbb", github_url="https://github.com/advisories/GHSA-bbbb-bbbb-bbbb"),
        ],
    )
    finding = _vuln_finding("pkg", {"id": "GHSA-aaaa-aaaa-aaaa"}, {"id": "GHSA-bbbb-bbbb-bbbb"})

    await service.enrich_findings([finding])

    assert "github_advisory_url" not in finding["details"]
    assert [e["github_advisory_url"].rsplit("/", 1)[1] for e in finding["details"]["vulnerabilities"]] == [
        "GHSA-aaaa-aaaa-aaaa",
        "GHSA-bbbb-bbbb-bbbb",
    ]


@pytest.mark.asyncio
async def test_only_findings_ghsa_resolution_touched_are_deduplicated(monkeypatch):
    from app.services.enrichment import service as service_module

    calls = []
    real = service_module.dedupe_vulnerability_entries
    monkeypatch.setattr(service_module, "dedupe_vulnerability_entries", lambda e: calls.append(len(e)) or real(e))
    service = _service(monkeypatch, ghsa=[GHSAData(ghsa_id="GHSA-aaaa-aaaa-aaaa", cve_id="CVE-2024-1")])
    touched = _vuln_finding("npm-pkg", {"id": "GHSA-aaaa-aaaa-aaaa"}, {"id": "CVE-2024-1"})
    untouched = _vuln_finding("linux-libc-dev", *({"id": f"CVE-2024-{n}0"} for n in range(5)))

    await service.enrich_findings([touched, untouched])

    assert calls == [2]
    assert len(touched["details"]["vulnerabilities"]) == 1


@pytest.mark.asyncio
async def test_the_result_does_not_depend_on_finding_or_entry_order(monkeypatch):
    kev = [_kev("CVE-1", "2025-03-01"), _kev("CVE-2", "2025-01-01", ransomware=True)]
    epss = [_epss("CVE-1", 0.4), _epss("CVE-2", 0.2), _epss("CVE-3", 0.7)]
    entries = [{"id": "CVE-1", "cvss_score": 7.0}, {"id": "CVE-2"}, {"id": "CVE-3", "cvss_score": 9.0}]
    outcomes = []
    for order in itertools.permutations(entries):
        finding = _vuln_finding("pkg", *order)
        await _service(monkeypatch, kev=kev, epss=epss).enrich_findings([finding])
        details = finding["details"]
        outcomes.append({k: v for k, v in details.items() if k != "vulnerabilities"})
    assert all(outcome == outcomes[0] for outcome in outcomes)
    assert outcomes[0]["kev_due_date"] == "2025-01-01"
    assert outcomes[0]["kev_ransomware_use"] is True
    assert outcomes[0]["epss_score"] == 0.7


@pytest.mark.asyncio
async def test_every_written_key_is_declared_at_its_level(monkeypatch):
    service = _service(monkeypatch, kev=[_kev("CVE-1", "2025-01-01")], epss=[_epss("CVE-1", 0.5)])
    finding = _vuln_finding("pkg", {"id": "CVE-1", "cvss_score": 7.5}, {"id": "GHSA-x", "cvss_score": 5.0})

    await service.enrich_findings([finding])

    details = finding["details"]
    assert set(details) <= set(VulnerabilityDetails.model_fields)
    for entry in details["vulnerabilities"]:
        assert set(entry) <= set(VulnerabilityEntryDetails.model_fields), entry


@pytest.mark.asyncio
async def test_the_per_cve_enrichment_of_a_bundled_advisory_is_handed_back(monkeypatch):
    service = _service(monkeypatch, kev=[_kev("CVE-2023-0002", "2024-01-01")])
    finding = _vuln_finding("openssl-libs", {"id": "CVE-2023-0001", "aliases": ["ALAS2-2023-2001", "CVE-2023-0002"]})

    threat_intel = await service.enrich_findings([finding])

    assert {cve: e.is_kev for cve, e in threat_intel.items()} == {"CVE-2023-0001": False, "CVE-2023-0002": True}
