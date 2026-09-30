"""GHSA-to-CVE resolution against GitHub's advisory API: credentials, rate limits and what gets cached."""

import asyncio
import time

import httpx
import pytest

from app.core.cache import CacheKeys, CacheTTL
from app.core.metrics import external_api_rate_limit_hits_total
from app.schemas.enrichment import GHSAData
from app.services.enrichment.service import vulnerability_enrichment_service
from tests.helpers.enrichment import Upstreams, github_advisory, serve_enrichment

_LOG4SHELL = "GHSA-jfh8-c2jp-5v3q"
_LOG4SHELL_CVE = "CVE-2021-44228"
_OTHER = "GHSA-7rjr-3q55-vv33"
_UNKNOWN = "GHSA-xxxx-xxxx-xxxx"
_ADVISORY_API_LABEL = "GitHub Advisory API"


def _finding(*ghsa_ids: str) -> dict:
    return {
        "component": "log4j-core",
        "version": "2.14.1",
        "details": {"vulnerabilities": [{"id": i} for i in ghsa_ids]},
    }


async def _resolve(*ghsa_ids: str, token: str | None = None) -> dict[str, GHSAData]:
    return await vulnerability_enrichment_service._ghsa_provider.resolve_ghsa_to_cve(list(ghsa_ids), token)


async def _exhausted(request: httpx.Request) -> httpx.Response:
    await asyncio.sleep(0)
    reset = str(int(time.time()) + 3600)
    return httpx.Response(403, headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": reset})


@pytest.mark.asyncio
async def test_a_token_removed_between_runs_is_no_longer_sent_to_github(fake_cache, monkeypatch):
    seen = serve_enrichment(monkeypatch, fake_cache, Upstreams(advisories={_LOG4SHELL: None, _OTHER: None}))

    await vulnerability_enrichment_service.enrich_findings([_finding(_LOG4SHELL)], github_token="ghp_old")
    await vulnerability_enrichment_service.enrich_findings([_finding(_OTHER)], github_token=None)

    github = [r for r in seen if r.url.host == "api.github.com"]
    assert [r.headers.get("Authorization") for r in github] == ["Bearer ghp_old", None]


@pytest.mark.asyncio
async def test_the_advisory_resolves_through_its_cve_id(fake_cache, monkeypatch):
    serve_enrichment(monkeypatch, fake_cache, Upstreams(advisories={_LOG4SHELL: _LOG4SHELL_CVE}))

    resolved = (await _resolve(_LOG4SHELL))[_LOG4SHELL]

    assert resolved.cve_id == _LOG4SHELL_CVE
    assert resolved.advisory_url == f"https://github.com/advisories/{_LOG4SHELL}"


@pytest.mark.asyncio
async def test_an_advisory_without_an_html_url_links_to_its_github_page(fake_cache, monkeypatch):
    serve_enrichment(
        monkeypatch, fake_cache, lambda r: httpx.Response(200, json=github_advisory(_LOG4SHELL, None, html_url=None))
    )

    resolved = (await _resolve(_LOG4SHELL))[_LOG4SHELL]

    assert resolved.advisory_url == f"https://github.com/advisories/{_LOG4SHELL}"


def test_an_unresolved_placeholder_links_to_its_github_page():
    assert GHSAData(ghsa_id=_UNKNOWN).advisory_url == f"https://github.com/advisories/{_UNKNOWN}"


@pytest.mark.asyncio
async def test_a_404_is_cached_as_unresolved_for_the_ghsa_ttl(fake_cache, monkeypatch):
    serve_enrichment(monkeypatch, fake_cache, Upstreams())

    resolved = (await _resolve(_UNKNOWN))[_UNKNOWN]

    assert resolved.cve_id is None
    assert (await fake_cache.get(CacheKeys.ghsa(_UNKNOWN)))["ghsa_id"] == _UNKNOWN
    assert await fake_cache._client.ttl(fake_cache._make_key(CacheKeys.ghsa(_UNKNOWN))) > CacheTTL.NEGATIVE_RESULT


@pytest.mark.asyncio
async def test_a_rate_limited_lookup_is_retried(fake_cache, monkeypatch):
    answers = [httpx.Response(429, headers={"Retry-After": "0"})]
    healthy = Upstreams(advisories={_LOG4SHELL: _LOG4SHELL_CVE})
    seen = serve_enrichment(monkeypatch, fake_cache, lambda r: answers.pop() if answers else healthy(r))

    resolved = (await _resolve(_LOG4SHELL))[_LOG4SHELL]

    assert resolved.cve_id == _LOG4SHELL_CVE
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_a_failed_lookup_is_retried_on_the_next_run(fake_cache, monkeypatch):
    serve_enrichment(monkeypatch, fake_cache, Upstreams(down=frozenset({"api.github.com"})))
    assert (await _resolve(_LOG4SHELL))[_LOG4SHELL].cve_id is None
    assert await fake_cache.get(CacheKeys.ghsa(_LOG4SHELL)) is None

    serve_enrichment(monkeypatch, fake_cache, Upstreams(advisories={_LOG4SHELL: _LOG4SHELL_CVE}))

    assert (await _resolve(_LOG4SHELL))[_LOG4SHELL].cve_id == _LOG4SHELL_CVE


@pytest.mark.asyncio
async def test_an_exhausted_quota_stops_every_lookup_until_it_resets(fake_cache, monkeypatch):
    seen = serve_enrichment(monkeypatch, fake_cache, _exhausted)
    ids = [f"GHSA-aaaa-bbbb-{n:04d}" for n in range(6)]
    hits_before = external_api_rate_limit_hits_total.labels(service=_ADVISORY_API_LABEL)._value.get()

    first = await _resolve(*ids)
    second = await _resolve(*ids)

    # Unauthenticated, two lookups are in flight when the first 403 arrives; none after it is sent.
    assert len(seen) == 2
    assert all(first[i].cve_id is None and second[i].cve_id is None for i in ids)
    assert list((await fake_cache.mget([CacheKeys.ghsa(i) for i in ids])).values()) == [None] * len(ids)
    assert external_api_rate_limit_hits_total.labels(service=_ADVISORY_API_LABEL)._value.get() == hits_before + 2


@pytest.mark.asyncio
async def test_each_ghsa_id_reads_its_own_cached_advisory(fake_cache, monkeypatch):
    serve_enrichment(monkeypatch, fake_cache, Upstreams(advisories={_LOG4SHELL: _LOG4SHELL_CVE}))
    await fake_cache.set(CacheKeys.ghsa(_OTHER), GHSAData(ghsa_id=_OTHER, cve_id="CVE-2022-22965").model_dump())

    result = await _resolve(_LOG4SHELL, _LOG4SHELL, _OTHER)

    assert result[_OTHER].cve_id == "CVE-2022-22965"
    assert result[_LOG4SHELL].cve_id == _LOG4SHELL_CVE


@pytest.mark.asyncio
async def test_an_exhausted_anonymous_quota_does_not_stop_authenticated_lookups(fake_cache, monkeypatch):
    """Ad-hoc runs look up anonymously on the same provider that scans use with the instance token."""
    healthy = Upstreams(advisories={_LOG4SHELL: _LOG4SHELL_CVE})
    serve_enrichment(monkeypatch, fake_cache, lambda r: healthy(r) if r.headers.get("Authorization") else _exhausted(r))
    await _resolve(_OTHER)

    assert (await _resolve(_LOG4SHELL, token="ghp_scan"))[_LOG4SHELL].cve_id == _LOG4SHELL_CVE
