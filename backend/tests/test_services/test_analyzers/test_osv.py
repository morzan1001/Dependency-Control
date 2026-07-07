"""Tests for the OSV analyzer's pure helpers.

We pin the CVSS-score-extraction and withdrawn-vulnerability rules here
so the regressions caught in the audit can't quietly come back. The full
HTTP path is exercised by integration tests; these are unit-level."""

from typing import Any, Dict, List, Optional

import pytest

from app.services.analyzers.osv import OSVAnalyzer


class TestParseCvssScore:
    """Audit P6.1: the previous parser returned the last vector segment
    (e.g. 'A:H') and tried to float() it, so any vector-string CVSS came
    back as None — we silently lost the score."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    def test_numeric_score_passthrough(self):
        assert self.analyzer._parse_cvss_score("7.5") == 7.5

    def test_zero_score(self):
        assert self.analyzer._parse_cvss_score("0.0") == 0.0

    def test_cvss_v3_vector_with_explicit_base_score(self):
        # Real-world OSV severity entries pair a vector with an explicit base
        # score; the parser should return the score, not crash on the vector.
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        # Without a separate score we can't recover one — None is correct.
        assert self.analyzer._parse_cvss_score(vector) is None

    def test_cvss_vector_with_trailing_score_segment(self):
        # Some sources append the numeric score after the vector, separated
        # by '/' — '<vector>/9.8'. Make sure we still get the number.
        appended = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/9.8"
        assert self.analyzer._parse_cvss_score(appended) == 9.8

    def test_garbage_input_returns_none(self):
        assert self.analyzer._parse_cvss_score("not-a-cvss-score") is None
        assert self.analyzer._parse_cvss_score("") is None


class TestWithdrawnVulnerabilities:
    """Audit P6.1: the OSV schema's `withdrawn` field marks retracted
    vulnerabilities. They were silently passed through as live findings."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    def test_withdrawn_vulnerabilities_are_dropped(self):
        vulns = [
            {"id": "GHSA-active", "summary": "live", "severity": [{"type": "CVSS_V3", "score": "7.5"}]},
            {
                "id": "GHSA-withdrawn",
                "summary": "retracted",
                "withdrawn": "2024-06-01T00:00:00Z",
                "severity": [{"type": "CVSS_V3", "score": "9.0"}],
            },
        ]
        normalized = self.analyzer._normalize_vulnerabilities(vulns)
        ids = [v["id"] for v in normalized]
        assert "GHSA-active" in ids
        assert "GHSA-withdrawn" not in ids

    def test_no_withdrawn_field_means_active(self):
        vulns = [{"id": "GHSA-x", "summary": "active"}]
        normalized = self.analyzer._normalize_vulnerabilities(vulns)
        assert len(normalized) == 1

    def test_empty_withdrawn_field_treated_as_active(self):
        # Defensive: empty string isn't a valid withdrawn timestamp, so the
        # vuln should be kept rather than silently dropped on schema noise.
        vulns = [{"id": "GHSA-x", "summary": "active", "withdrawn": ""}]
        normalized = self.analyzer._normalize_vulnerabilities(vulns)
        assert len(normalized) == 1


class TestCvssVersionAwareSeverity:
    """Audit P7.2: CVSS v2 has no CRITICAL bucket — its top tier is HIGH.
    The mapper used to apply v3 thresholds to every CVSS score regardless of
    the source version, so a v2 score of 9.5 was upgraded to CRITICAL when
    it should remain HIGH."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    def test_cvss_v2_top_score_is_high_not_critical(self):
        # v2 spec: 7.0-10.0 = HIGH. There is no CRITICAL bucket.
        result = self.analyzer._severity_from_cvss_array([{"type": "CVSS_V2", "score": "9.5"}])
        assert result == "HIGH"

    def test_cvss_v3_critical_score_is_critical(self):
        result = self.analyzer._severity_from_cvss_array([{"type": "CVSS_V3", "score": "9.5"}])
        assert result == "CRITICAL"

    def test_v3_preferred_over_v2_when_both_present(self):
        # An OSV record with both v2 and v3 scores: prefer the newer standard.
        result = self.analyzer._severity_from_cvss_array(
            [
                {"type": "CVSS_V2", "score": "9.5"},
                {"type": "CVSS_V3", "score": "5.0"},
            ]
        )
        # v3 wins -> 5.0 -> MEDIUM
        assert result == "MEDIUM"

    def test_v4_preferred_over_v3(self):
        # CVSS v4 supersedes v3 — pick the newest available standard.
        result = self.analyzer._severity_from_cvss_array(
            [
                {"type": "CVSS_V3", "score": "9.5"},
                {"type": "CVSS_V4", "score": "5.0"},
            ]
        )
        assert result == "MEDIUM"

    def test_score_above_10_is_clamped(self):
        # Defensive: CVSS scores are bounded at 10.0. A bogus 15.0 must
        # not silently round-trip to CRITICAL — clamp into the valid range
        # so the resulting severity stays meaningful.
        result = self.analyzer._severity_from_cvss_array([{"type": "CVSS_V3", "score": "15.0"}])
        assert result == "CRITICAL"  # clamped to 10.0, still in CRITICAL bucket

    def test_score_below_zero_is_clamped(self):
        result = self.analyzer._severity_from_cvss_array([{"type": "CVSS_V3", "score": "-1.0"}])
        assert result == "LOW"


class _Response:
    """Minimal stand-in for httpx.Response."""

    def __init__(self, status_code: int, payload: Optional[Dict[str, Any]] = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> Dict[str, Any]:
        return self._payload


class _FakeCache:
    """In-memory replacement for cache_service (mget/mset only)."""

    def __init__(self) -> None:
        self.store: Dict[str, Any] = {}

    async def mget(self, keys: List[str]) -> Dict[str, Any]:
        return {k: self.store.get(k) for k in keys}

    async def mset(self, mapping: Dict[str, Any], ttl_seconds: int = 0) -> None:  # noqa: ARG002
        self.store.update(mapping)


def _scripted_client_factory(responses: List[_Response], call_counter: List[int]):
    """Build an InstrumentedAsyncClient replacement that returns ``responses``
    in order (repeating the last one once exhausted) and counts .post calls."""

    class _ScriptedClient:
        def __init__(self, *_a: Any, **_k: Any) -> None: ...

        async def __aenter__(self) -> "_ScriptedClient":
            return self

        async def __aexit__(self, *_a: Any) -> None:
            return None

        async def post(self, _url: str, **_kwargs: Any) -> _Response:
            idx = min(call_counter[0], len(responses) - 1)
            call_counter[0] += 1
            return responses[idx]

    return _ScriptedClient


def _vuln_response() -> _Response:
    return _Response(
        200,
        {
            "results": [
                {"vulns": [{"id": "GHSA-boom", "summary": "bad", "severity": [{"type": "CVSS_V3", "score": "9.8"}]}]}
            ]
        },
    )


class TestRateLimitRetry:
    """Audit bug/medium: a 429 used to sleep but never re-POST the chunk, so
    up to 500 components per throttled chunk were silently dropped from the
    scan (uncached and absent from results). The chunk must be retried."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()
        self.component = {
            "name": "boompkg",
            "version": "1.0.0",
            "purl": "pkg:pypi/boompkg@1.0.0",
        }

    @pytest.mark.asyncio
    async def test_rate_limited_chunk_is_retried_and_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # First POST is throttled (429), the retry returns real vulns.
        counter = [0]
        client_cls = _scripted_client_factory([_Response(429), _vuln_response()], counter)
        monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", client_cls)
        monkeypatch.setattr("app.services.analyzers.osv.cache_service", _FakeCache())
        monkeypatch.setattr("app.services.analyzers.osv.asyncio.sleep", _noop_sleep)

        results: List[Dict[str, Any]] = []
        await self.analyzer._fetch_uncached([self.component], results)

        # The chunk was re-POSTed after the 429, so the vuln surfaces.
        assert counter[0] == 2
        assert len(results) == 1
        assert results[0]["component"] == "boompkg"
        assert results[0]["vulnerabilities"][0]["id"] == "GHSA-boom"

    @pytest.mark.asyncio
    async def test_persistent_rate_limit_gives_up_after_bounded_attempts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Always 429 -> bounded number of attempts, no infinite loop, no results.
        counter = [0]
        client_cls = _scripted_client_factory([_Response(429)], counter)
        monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", client_cls)
        monkeypatch.setattr("app.services.analyzers.osv.cache_service", _FakeCache())
        monkeypatch.setattr("app.services.analyzers.osv.asyncio.sleep", _noop_sleep)

        results: List[Dict[str, Any]] = []
        await self.analyzer._fetch_uncached([self.component], results)

        assert counter[0] == 1 + self.analyzer.max_retries
        assert results == []

    @pytest.mark.asyncio
    async def test_success_first_try_does_not_retry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        counter = [0]
        client_cls = _scripted_client_factory([_vuln_response()], counter)
        monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", client_cls)
        monkeypatch.setattr("app.services.analyzers.osv.cache_service", _FakeCache())
        monkeypatch.setattr("app.services.analyzers.osv.asyncio.sleep", _noop_sleep)

        results: List[Dict[str, Any]] = []
        await self.analyzer._fetch_uncached([self.component], results)

        assert counter[0] == 1
        assert len(results) == 1


async def _noop_sleep(_seconds: float) -> None:
    """Skip real backoff delays in tests."""
    return None
