"""Unit tests for the OSV analyzer's pure helpers (CVSS-score extraction, withdrawn handling)."""

from typing import Any

import pytest
from typing_extensions import Self

from app.services.analyzers.osv import OSVAnalyzer


class TestParseCvssScore:
    """_parse_cvss_score: numeric scores pass through, vectors are scored."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            pytest.param("7.5", 7.5, id="numeric-passthrough"),
            pytest.param("0.0", 0.0, id="zero"),
            # OSV rates with a vector and no number; returning None here discards the rating.
            pytest.param("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, id="bare-v3-vector"),
            # 9.3 as published by FIRST's own calculator for this vector.
            pytest.param("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, id="bare-v4-vector"),
        ],
    )
    def test_a_rated_input_yields_its_score(self, raw, expected):
        assert self.analyzer._parse_cvss_score(raw) == expected

    def test_v2_vector_returns_none(self):
        # No source in the corpus carries v2; it stays unscored rather than mis-scored as v3.
        assert self.analyzer._parse_cvss_score("AV:N/AC:L/Au:N/C:P/I:P/A:P") is None

    def test_garbage_input_returns_none(self):
        assert self.analyzer._parse_cvss_score("not-a-cvss-score") is None
        assert self.analyzer._parse_cvss_score("") is None


class TestWithdrawnVulnerabilities:
    """Vulnerabilities carrying a `withdrawn` timestamp are dropped."""

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

    @pytest.mark.parametrize(
        "vuln",
        [
            pytest.param({"id": "GHSA-x", "summary": "active"}, id="no-withdrawn-field"),
            # An empty string isn't a valid withdrawn timestamp; keep the vuln.
            pytest.param({"id": "GHSA-x", "summary": "active", "withdrawn": ""}, id="empty-withdrawn-field"),
        ],
    )
    def test_a_vuln_without_a_withdrawn_timestamp_is_kept(self, vuln):
        normalized = self.analyzer._normalize_vulnerabilities([vuln])
        assert len(normalized) == 1


class TestNormalizedEntryShape:
    """The shape normalize_osv consumes. Reading anything else there yields UNKNOWN severities."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    def test_severity_is_a_resolved_top_level_string(self):
        vulns = [
            {
                "id": "GHSA-x",
                "summary": "s",
                "database_specific": {"severity": "MODERATE"},
                "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            }
        ]
        entry = self.analyzer._normalize_vulnerabilities(vulns)[0]
        assert entry["severity"] == "MEDIUM"
        assert "database_specific" not in entry


class TestCvssVersionAwareSeverity:
    """CVSS v2 has no CRITICAL bucket (top tier is HIGH); the mapper must respect the source version."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()

    @pytest.mark.parametrize(
        ("severity_array", "expected"),
        [
            # v2 spec: 7.0-10.0 = HIGH; there is no CRITICAL bucket.
            pytest.param([{"type": "CVSS_V2", "score": "9.5"}], "HIGH", id="v2-top-score-is-high"),
            pytest.param([{"type": "CVSS_V3", "score": "9.5"}], "CRITICAL", id="v3-critical-score"),
            # Both v2 and v3 present: prefer the newer standard -> 5.0 -> MEDIUM.
            pytest.param(
                [{"type": "CVSS_V2", "score": "9.5"}, {"type": "CVSS_V3", "score": "5.0"}],
                "MEDIUM",
                id="v3-preferred-over-v2",
            ),
            # CVSS v4 supersedes v3 — pick the newest available standard.
            pytest.param(
                [{"type": "CVSS_V3", "score": "9.5"}, {"type": "CVSS_V4", "score": "5.0"}],
                "MEDIUM",
                id="v4-preferred-over-v3",
            ),
            # CVSS scores are bounded at 10.0; a bogus 15.0 clamps into range.
            pytest.param([{"type": "CVSS_V3", "score": "15.0"}], "CRITICAL", id="score-above-10-clamped"),
            pytest.param([{"type": "CVSS_V3", "score": "-1.0"}], "LOW", id="score-below-zero-clamped"),
            # 9.0 is the inclusive floor of the CRITICAL band and a score NVD publishes often.
            pytest.param([{"type": "CVSS_V3", "score": "9.0"}], "CRITICAL", id="v3-exactly-nine"),
            pytest.param([{"type": "CVSS_V3", "score": "8.9"}], "HIGH", id="v3-just-below-nine"),
        ],
    )
    def test_the_severity_comes_from_the_newest_rating_in_range(self, severity_array, expected):
        assert self.analyzer._severity_from_cvss_array(severity_array) == expected


class _Response:
    """Minimal stand-in for httpx.Response."""

    def __init__(self, status_code: int, payload: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeCache:
    """In-memory replacement for cache_service (mget/mset only)."""

    def __init__(self) -> None:
        self.store: dict[str, Any] = {}

    async def mget(self, keys: list[str]) -> dict[str, Any]:
        return {k: self.store.get(k) for k in keys}

    async def mset(self, mapping: dict[str, Any], ttl_seconds: int = 0) -> None:
        self.store.update(mapping)


def _scripted_client_factory(responses: list[_Response], call_counter: list[int]):
    """InstrumentedAsyncClient replacement returning ``responses`` in order (repeating the last) and counting .post calls."""

    class _ScriptedClient:
        def __init__(self, *_a: Any, **_k: Any) -> None: ...

        async def __aenter__(self) -> Self:
            return self

        async def __aexit__(self, *_a: object) -> None:
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
    """A 429 must retry the chunk, not silently drop up to 500 components."""

    def setup_method(self):
        self.analyzer = OSVAnalyzer()
        self.component = {
            "name": "boompkg",
            "version": "1.0.0",
            "purl": "pkg:pypi/boompkg@1.0.0",
        }

    @pytest.mark.asyncio
    async def test_rate_limited_chunk_is_retried_and_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # First POST is throttled (429); the retry returns real vulns.
        counter = [0]
        client_cls = _scripted_client_factory([_Response(429), _vuln_response()], counter)
        monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", client_cls)
        monkeypatch.setattr("app.services.analyzers.osv.cache_service", _FakeCache())
        monkeypatch.setattr("app.services.analyzers.osv.asyncio.sleep", _noop_sleep)

        results: list[dict[str, Any]] = []
        await self.analyzer._fetch_uncached([self.component], results)

        assert counter[0] == 2
        assert len(results) == 1
        assert results[0]["component"] == "boompkg"
        assert results[0]["vulnerabilities"][0]["id"] == "GHSA-boom"

    @pytest.mark.asyncio
    async def test_persistent_rate_limit_gives_up_after_bounded_attempts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Always 429 -> bounded attempts, no infinite loop, no results.
        counter = [0]
        client_cls = _scripted_client_factory([_Response(429)], counter)
        monkeypatch.setattr("app.services.analyzers.osv.InstrumentedAsyncClient", client_cls)
        monkeypatch.setattr("app.services.analyzers.osv.cache_service", _FakeCache())
        monkeypatch.setattr("app.services.analyzers.osv.asyncio.sleep", _noop_sleep)

        results: list[dict[str, Any]] = []
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

        results: list[dict[str, Any]] = []
        await self.analyzer._fetch_uncached([self.component], results)

        assert counter[0] == 1
        assert len(results) == 1


async def _noop_sleep(_seconds: float) -> None:
    """Skip real backoff delays in tests."""
    return


class TestParseCvssScoreNonFinite:
    """float() accepts "nan"/"inf"; NaN survives _cvss_to_severity's clamp as 10.0 because no
    comparison against it is true, so it would land in CRITICAL despite the clamp."""

    @pytest.mark.parametrize("score", ["nan", "NaN", "inf", "-inf", "infinity"])
    def test_non_finite_scores_do_not_produce_a_severity(self, score):
        assert OSVAnalyzer()._parse_cvss_score(score) is None

    def test_a_nan_severity_entry_leaves_the_record_unrated(self):
        record = {"id": "CVE-2026-1", "severity": [{"type": "CVSS_V3", "score": "nan"}]}
        assert OSVAnalyzer()._extract_severity(record) == "UNKNOWN"

    def test_a_finite_out_of_range_score_is_still_clamped(self):
        assert OSVAnalyzer()._cvss_to_severity(42.0) == "CRITICAL"
        assert OSVAnalyzer()._cvss_to_severity(-5.0) == "LOW"


class TestV4OnlyRecords:
    """A live census of 369 OSV records fetched for production findings found 28 rated only by
    a CVSS:4.0 vector with no database_specific.severity — 28 of the 44 that derived UNKNOWN."""

    @pytest.mark.parametrize(
        ("record", "expected"),
        [
            # CVE-2025-55163, exactly as OSV serves it.
            pytest.param(
                {
                    "id": "CVE-2025-55163",
                    "severity": [
                        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"}
                    ],
                },
                "HIGH",
                id="v4-only-record",
            ),
            # _CVSS_TYPE_PREFERENCE puts v4 first: v4 scores 5.4 (MEDIUM), the v3 vector 7.8 (HIGH).
            pytest.param(
                {
                    "id": "CVE-2024-56326",
                    "severity": [
                        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
                        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
                    ],
                },
                "MEDIUM",
                id="v4-preferred-over-v3",
            ),
            pytest.param(
                {
                    "id": "CVE-2026-2",
                    "severity": [
                        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L"},
                        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                    ],
                },
                "CRITICAL",
                id="unparseable-v4-falls-through-to-v3",
            ),
            pytest.param({"id": "CVE-2026-3", "severity": []}, "UNKNOWN", id="unrated-record"),
        ],
    )
    def test_the_record_is_rated_from_its_newest_usable_vector(self, record, expected):
        assert OSVAnalyzer()._extract_severity(record) == expected
