"""Aggregator enrichment entries, and the three vulnerability-enrichment upstreams answered in-process."""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from app.core.config import settings
from app.core.http_utils import InstrumentedAsyncClient
from app.services.enrichment import epss, ghsa, kev
from app.services.enrichment.service import vulnerability_enrichment_service

GITHUB_HOST = "api.github.com"
FIRST_HOST = "api.first.org"
CISA_HOST = "www.cisa.gov"


def enrichment_payload(aggregator, name: str, version: str) -> dict:
    for entry in aggregator.get_dependency_enrichments():
        if entry["name"] == name and entry["version"] == version:
            return entry["data"]
    raise AssertionError(f"no enrichment entry for {name}@{version}")


def github_advisory(ghsa_id: str, cve_id: str | None, html_url: str | None = "") -> dict[str, Any]:
    """GET /advisories/{ghsa_id} as api.github.com answers it, trimmed of lists the parser never reads."""
    identifiers = [{"value": ghsa_id, "type": "GHSA"}] + ([{"value": cve_id, "type": "CVE"}] if cve_id else [])
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "url": f"https://api.github.com/advisories/{ghsa_id}",
        "html_url": f"https://github.com/advisories/{ghsa_id}" if html_url == "" else html_url,
        "summary": "Remote code injection",
        "type": "reviewed",
        "severity": "critical",
        "identifiers": identifiers,
        "published_at": "2021-12-10T00:40:56Z",
        "updated_at": "2026-09-01T00:00:00Z",
        "withdrawn_at": None,
    }


def epss_page(scores: dict[str, float]) -> dict[str, Any]:
    """FIRST.org's /data/v1/epss envelope; it leaves CVEs it has no score for out of ``data``."""
    return {
        "status": "OK",
        "status-code": 200,
        "total": len(scores),
        "offset": 0,
        "limit": 100,
        "data": [
            {"cve": cve, "epss": f"{score:.9f}", "percentile": "0.500000000", "date": "2026-09-29"}
            for cve, score in scores.items()
        ],
    }


def kev_feed(*cves: str) -> dict[str, Any]:
    """The CISA KEV JSON feed with one entry per CVE."""
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.09.29",
        "count": len(cves),
        "vulnerabilities": [
            {
                "cveID": cve,
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
                "dateAdded": "2021-12-10",
                "shortDescription": "JNDI features do not protect against attacker-controlled LDAP.",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
                "notes": "",
            }
            for cve in cves
        ],
    }


@dataclass
class Upstreams:
    """GitHub, FIRST.org and CISA answering in their real shapes; a host in ``down`` answers 503."""

    advisories: dict[str, str | None] = field(default_factory=dict)
    scores: dict[str, float] = field(default_factory=dict)
    kev: tuple[str, ...] = ()
    down: frozenset[str] = frozenset()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host in self.down:
            return httpx.Response(503)
        if host == GITHUB_HOST:
            ghsa_id = request.url.path.rsplit("/", 1)[1]
            if ghsa_id not in self.advisories:
                return httpx.Response(404, json={"message": "Not Found"})
            return httpx.Response(200, json=github_advisory(ghsa_id, self.advisories[ghsa_id]))
        if host == FIRST_HOST:
            asked = request.url.params["cve"].split(",")
            return httpx.Response(200, json=epss_page({c: self.scores[c] for c in asked if c in self.scores}))
        if host == CISA_HOST:
            return httpx.Response(200, json=kev_feed(*self.kev))
        raise AssertionError(f"unexpected upstream {request.url}")


def serve_enrichment(
    monkeypatch: pytest.MonkeyPatch, cache: Any, handler: Callable[[httpx.Request], Any]
) -> list[httpx.Request]:
    """Answer every EPSS, KEV and GHSA request with ``handler`` over ``cache``, on fresh providers with backoff
    delays zeroed; returns the requests in arrival order."""
    seen: list[httpx.Request] = []

    def _record(request: httpx.Request) -> Any:
        seen.append(request)
        return handler(request)

    transport = httpx.MockTransport(_record)
    monkeypatch.setattr(settings, "ENRICHMENT_RETRY_DELAY", 0.0)
    for module in (epss, kev, ghsa):
        monkeypatch.setattr(
            module,
            "InstrumentedAsyncClient",
            lambda service, **kwargs: InstrumentedAsyncClient(service, transport=transport, **kwargs),
        )
        monkeypatch.setattr(module, "cache_service", cache)
    for attribute, provider in (
        ("_epss_provider", epss.EPSSProvider),
        ("_kev_provider", kev.KEVProvider),
        ("_ghsa_provider", ghsa.GHSAProvider),
    ):
        monkeypatch.setattr(vulnerability_enrichment_service, attribute, provider())
    return seen
