"""End-of-life detection: components resolve to endoflife.date products, versions to that product's release cycles."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Self

import httpx
import pytest

from app.core.constants import EOL_API_URL
from app.models.finding import Severity
from app.services.aggregation import ResultAggregator
from app.services.analyzers import end_of_life
from app.services.analyzers.end_of_life import (
    EndOfLifeAnalyzer,
    _check_version,
    _version_matches_cycle,
    collect_products_to_check,
)
from tests.helpers.analyzers import analyze_cyclonedx

# /api/all.json of endoflife.date, fetched 2026-09-29.
_PRODUCT_INDEX = json.loads((Path(__file__).parents[2] / "fixtures" / "endoflife_products.json").read_text())


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")


def _days_ahead(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d")


def _cycle(cycle: str, eol: Any, latest: str, lts: bool = False) -> dict[str, Any]:
    return {"cycle": cycle, "releaseDate": "2015-01-01", "eol": eol, "latest": latest, "lts": lts}


# Cycle lists in the shape of /api/<product>.json, newest cycle first.
_OPENSSL = [
    _cycle("3.5", _days_ahead(1500), "3.5.0", lts=True),
    _cycle("1.1.1", _days_ago(1100), "1.1.1w", lts=True),
    _cycle("1.1.0", _days_ago(2500), "1.1.0l"),
    _cycle("1.0.2", _days_ago(2400), "1.0.2u", lts=True),
    _cycle("0.9.8", _days_ago(3900), "0.9.8zh"),
]
_NODEJS = [_cycle("22", _days_ahead(600), "22.9.0", lts=True), _cycle("16", _days_ago(1100), "16.20.2", lts=True)]
_PERL = [_cycle("5.40", False, "5.40.0"), _cycle("5.32", True, "5.32.1")]
_GO = [_cycle("1.23", False, "1.23.1"), _cycle("1.19", _days_ago(1300), "1.19.13")]
_NGINX = [
    _cycle("1.29", False, "1.29.1"),
    _cycle("1.28", _days_ago(400), "1.28.3"),
    _cycle("1.22", _days_ago(900), "1.22.1"),
]
_SPRING_BOOT = [_cycle("3.3", _days_ahead(200), "3.3.4"), _cycle("2.5", _days_ago(1400), "2.5.15")]
_HTTPD = [_cycle("2.4", False, "2.4.62"), _cycle("2.2", _days_ago(2800), "2.2.34")]
_AMAZON_LINUX = [
    _cycle("2023", _days_ahead(900), "2023.5"),
    _cycle("2", _days_ago(90), "2.0.20250929"),
    _cycle("2018.03", _days_ago(1000), "2018.03.0"),
]
_ORACLE_LINUX = [_cycle("9", _days_ahead(2000), "9.4"), _cycle("7", _days_ago(600), "7.9")]
_OPENSUSE = [_cycle("15.6", _days_ahead(300), "15.6"), _cycle("15.3", _days_ago(900), "15.3")]
_ANGULARJS = [_cycle("1.8", _days_ago(1000), "1.8.3"), _cycle("1.7", _days_ago(1500), "1.7.9")]
_PYTHON = [_cycle("3.13", _days_ahead(1500), "3.13.0"), _cycle("2.7", True, "2.7.18")]


class _EndOfLifeDate:
    """endoflife.date: the product index, a cycle list for each product it serves, and 404 for anything else."""

    def __init__(self, cycles: dict[str, Any], index: Any = _PRODUCT_INDEX, index_status: int = 200):
        self.cycles = cycles
        self.index = index
        self.index_status = index_status
        self.requested: list[str] = []

    def __call__(self, *_args: Any, **_kwargs: Any) -> Self:
        return self

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def get(self, url: str) -> httpx.Response:
        slug = url.removeprefix(f"{EOL_API_URL}/").removesuffix(".json")
        self.requested.append(slug)
        if slug == "all":
            return httpx.Response(self.index_status, json=self.index)
        if slug in self.cycles:
            return httpx.Response(200, json=self.cycles[slug])
        return httpx.Response(404, json={"message": "Product not found"})


class _MemoryCache:
    """cache_service's locked fetch: a stored value wins, a fetch result is stored, None stores the failure marker."""

    def __init__(self) -> None:
        self.entries: dict[str, Any] = {}

    async def get_or_fetch_with_lock(self, key: str, fetch_fn, ttl_seconds: int | None = None) -> Any:
        if self.entries.get(key) is not None:
            return self.entries[key]
        value = await fetch_fn()
        self.entries[key] = {} if value is None else value
        return value


@pytest.fixture
def serve(monkeypatch: pytest.MonkeyPatch):
    def _serve(cycles: dict[str, Any], **index: Any) -> tuple[_EndOfLifeDate, _MemoryCache]:
        upstream, cache = _EndOfLifeDate(cycles, **index), _MemoryCache()
        monkeypatch.setattr(end_of_life, "InstrumentedAsyncClient", upstream)
        monkeypatch.setattr(end_of_life, "cache_service", cache)
        return upstream, cache

    return _serve


def _component(name: str, version: str, purl: str | None = None, cpe: str | None = None, **extra: Any) -> dict:
    component = {"type": "library", "name": name, "version": version, **extra}
    if purl:
        component["purl"] = purl
    if cpe:
        component["cpe"] = cpe
    return component


def _openssl_binary(version: str) -> dict:
    """Syft's binary classifier: an application component identified by its CPE."""
    return _component("openssl", version, cpe=f"cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*", type="application")


def _os(name: str, version: str) -> dict:
    return {"type": "operating-system", "name": name, "version": version}


async def _issues(components: list[dict], settings: dict | None = None) -> list[dict]:
    return (await analyze_cyclonedx(EndOfLifeAnalyzer(), components, settings))["eol_issues"]


def _cycles_of(issues: list[dict]) -> dict[str, str]:
    return {issue["component"]: issue["eol_info"]["cycle"] for issue in issues}


class TestVersionMatchesCycle:
    @pytest.mark.parametrize(
        ("version", "cycle", "expected"),
        [
            pytest.param("3.8", "3.8", True, id="exact"),
            pytest.param("3.8.5", "3.8", True, id="patch-of-cycle"),
            pytest.param("3.8.5", "3", True, id="major-cycle"),
            pytest.param("1.1.1w", "1.1.1", True, id="openssl-letter-release"),
            pytest.param("1.1.1n-0+deb11u5", "1.1.1", True, id="openssl-debian-build"),
            pytest.param("1.1.1-1ubuntu2.1~18.04.23", "1.1.1", True, id="openssl-ubuntu-build"),
            pytest.param("0.9.8zh", "0.9.8", True, id="openssl-double-letter"),
            pytest.param("1.1.10", "1.1.1", False, id="longer-number-is-another-release"),
            pytest.param("3.10.2", "3.1", False, id="minor-10-is-not-minor-1"),
            pytest.param("3.80", "3.8", False, id="minor-80-is-not-minor-8"),
            pytest.param("3.8.5", "3.9", False, id="other-minor"),
            pytest.param("", "3.8", False, id="empty-version"),
            pytest.param("3.8.5", "", False, id="empty-cycle"),
        ],
    )
    def test_a_version_belongs_to_a_cycle_it_extends_with_a_non_digit(self, version, cycle, expected):
        assert _version_matches_cycle(version, cycle) is expected


class TestCheckVersion:
    @pytest.mark.parametrize(
        ("version", "expected_cycle"),
        [
            pytest.param("v2.7.18", "2.7", id="v-prefix"),
            pytest.param("V2.7.18", "2.7", id="upper-case-v-prefix"),
            pytest.param("1:2.7.18-4.el9", "2.7", id="rpm-epoch"),
        ],
    )
    def test_version_decoration_does_not_hide_the_cycle(self, version, expected_cycle):
        assert _check_version(version, _PYTHON)["cycle"] == expected_cycle

    @pytest.mark.parametrize(
        "version",
        [
            pytest.param("3.13.0", id="cycle-still-supported"),
            pytest.param("3.12.0", id="no-cycle-matches"),
            pytest.param("", id="no-version"),
        ],
    )
    def test_a_supported_or_unknown_version_is_not_end_of_life(self, version):
        assert _check_version(version, _PYTHON) is None

    def test_the_most_specific_cycle_decides(self):
        cycles = [_cycle("3", _days_ago(3000), "3.99"), _cycle("3.8", _days_ahead(300), "3.8.99")]
        assert _check_version("3.8.0", cycles) is None

    def test_lts_wins_a_tie_between_equally_specific_cycles(self):
        cycles = [_cycle("8", _days_ago(300), "8.0.1"), _cycle("8", _days_ahead(300), "8.0.2", lts=True)]
        assert _check_version("8.0.342", cycles) is None


class TestSeverity:
    @pytest.mark.parametrize(
        ("eol", "expected"),
        [
            pytest.param(True, Severity.HIGH.value, id="eol-without-date"),
            pytest.param(_days_ago(365), Severity.HIGH.value, id="exactly-high-threshold"),
            pytest.param(_days_ago(364), Severity.MEDIUM.value, id="just-below-high"),
            pytest.param(_days_ago(180), Severity.MEDIUM.value, id="exactly-medium-threshold"),
            pytest.param(_days_ago(179), Severity.LOW.value, id="just-below-medium"),
        ],
    )
    @pytest.mark.asyncio
    async def test_severity_grows_with_the_days_past_eol(self, serve, eol, expected):
        serve({"python": [_cycle("3.13", False, "3.13.0"), _cycle("3.6", eol, "3.6.15")]})

        [issue] = await _issues([_component("python", "3.6.15", "pkg:generic/python@3.6.15")])

        assert issue["severity"] == expected

    @pytest.mark.asyncio
    async def test_the_project_thresholds_apply(self, serve):
        serve({"python": [_cycle("3.6", _days_ago(60), "3.6.15")]})
        components = [_component("python", "3.6.15", "pkg:generic/python@3.6.15")]

        [issue] = await _issues(components, {"eol_high_after_days": 30, "eol_medium_after_days": 15})

        assert issue["severity"] == Severity.HIGH.value


class TestVersionsThatNamedTheirCycle:
    @pytest.mark.parametrize(
        ("version", "expected_cycle"),
        [
            pytest.param("1.1.1w", "1.1.1", id="openssl-1.1.1w"),
            pytest.param("1.0.2k-fips", "1.0.2", id="amazon-linux-openssl-1.0.2k-fips"),
            pytest.param("0.9.8zh", "0.9.8", id="openssl-0.9.8zh"),
        ],
    )
    @pytest.mark.asyncio
    async def test_letter_suffixed_openssl_releases_reach_their_cycle(self, serve, version, expected_cycle):
        serve({"openssl": _OPENSSL})

        issues = await _issues([_openssl_binary(version)])

        assert _cycles_of(issues) == {"openssl": expected_cycle}

    @pytest.mark.parametrize(
        ("component", "product", "expected_cycle"),
        [
            pytest.param(
                _component("nodejs", "1:16.20.2-3.el9_2", "pkg:rpm/redhat/nodejs@1:16.20.2-3.el9_2?distro=rhel-9"),
                "nodejs",
                "16",
                id="rhel-nodejs-with-epoch",
            ),
            pytest.param(
                _component("perl", "4:5.32.1-480.el9", "pkg:rpm/redhat/perl@4:5.32.1-480.el9?distro=rhel-9"),
                "perl",
                "5.32",
                id="rhel-perl-with-epoch",
            ),
            pytest.param(
                _component(
                    "stdlib",
                    "go1.19.4",
                    "pkg:golang/stdlib@go1.19.4",
                    "cpe:2.3:a:golang:go:1.19.4:-:*:*:*:*:*:*",
                ),
                "go",
                "1.19",
                id="syft-go-stdlib",
            ),
            pytest.param(
                _component("stdlib", "v1.19.4", "pkg:golang/stdlib@v1.19.4"), "go", "1.19", id="trivy-go-stdlib"
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_epoch_and_toolchain_prefixes_do_not_hide_the_cycle(self, serve, component, product, expected_cycle):
        serve({"nodejs": _NODEJS, "perl": _PERL, "go": _GO})

        [issue] = await _issues([component])

        assert (issue["product"], issue["eol_info"]["cycle"]) == (product, expected_cycle)


class TestOperatingSystems:
    @pytest.mark.parametrize(
        ("name", "version", "product", "expected_cycle"),
        [
            pytest.param("amzn", "2018.03", "amazon-linux", "2018.03", id="syft-amazon-linux"),
            pytest.param("ol", "7.9", "oracle-linux", "7", id="syft-oracle-linux"),
            pytest.param("opensuse-leap", "15.3", "opensuse", "15.3", id="syft-opensuse-leap"),
            pytest.param("oracle", "7.9", "oracle-linux", "7", id="trivy-oracle-linux"),
            pytest.param("amazon", "2 (Karoo)", "amazon-linux", "2", id="trivy-amazon-linux-with-codename"),
        ],
    )
    @pytest.mark.asyncio
    async def test_os_release_ids_reach_their_product(self, serve, name, version, product, expected_cycle):
        serve({"amazon-linux": _AMAZON_LINUX, "oracle-linux": _ORACLE_LINUX, "opensuse": _OPENSUSE})

        [issue] = await _issues([_os(name, version)])

        assert (issue["product"], issue["eol_info"]["cycle"]) == (product, expected_cycle)

    @pytest.mark.asyncio
    async def test_a_library_sharing_an_os_id_is_no_operating_system(self, serve):
        upstream, _ = serve({"oracle-linux": _ORACLE_LINUX})

        assert await _issues([_component("ol", "7.9.0", "pkg:npm/ol@7.9.0")]) == []
        assert upstream.requested == ["all"]


class TestProductResolution:
    @pytest.mark.parametrize(
        ("component", "product"),
        [
            pytest.param(
                _component(
                    "spring-boot",
                    "2.5.0",
                    "pkg:maven/org.springframework.boot/spring-boot@2.5.0",
                    "cpe:2.3:a:vmware:spring_boot:2.5.0:*:*:*:*:*:*:*",
                ),
                "spring-boot",
                id="nvd-underscore-product",
            ),
            pytest.param(
                _component(
                    "httpd", "2.2.34", cpe="cpe:2.3:a:apache:http_server:2.2.34:*:*:*:*:*:*:*", type="application"
                ),
                "apache-http-server",
                id="nvd-http-server",
            ),
            pytest.param(
                _component(
                    "libnode72", "16.20.2", cpe="cpe:2.3:a:nodejs:node\\.js:16.20.2:*:*:*:*:*:*:*", type="application"
                ),
                "nodejs",
                id="escaped-cpe-product",
            ),
        ],
    )
    @pytest.mark.asyncio
    async def test_nvd_cpe_spellings_reach_the_product(self, serve, component, product):
        serve({"spring-boot": _SPRING_BOOT, "apache-http-server": _HTTPD, "nodejs": _NODEJS})

        [issue] = await _issues([component])

        assert issue["product"] == product

    @pytest.mark.asyncio
    async def test_only_products_endoflife_date_lists_are_looked_up(self, serve):
        upstream, _ = serve({"openssl": _OPENSSL})
        components = [
            _openssl_binary("1.1.1w"),
            _component(
                "aiohttp",
                "3.9.0",
                "pkg:pypi/aiohttp@3.9.0",
                "cpe:2.3:a:python-aiohttp:python_aiohttp:3.9.0:*:*:*:*:*:*:*",
            ),
            _component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0"),
        ]

        issues = await _issues(components)

        assert _cycles_of(issues) == {"openssl": "1.1.1"}
        assert upstream.requested == ["all", "openssl"]

    @pytest.mark.asyncio
    async def test_a_component_named_all_neither_fetches_the_index_as_cycles_nor_breaks_the_scan(self, serve):
        upstream, cache = serve({"openssl": _OPENSSL})

        issues = await _issues([_component("all", "0.0.1", "pkg:npm/all@0.0.1"), _openssl_binary("1.1.1w")])

        assert _cycles_of(issues) == {"openssl": "1.1.1"}
        assert upstream.requested.count("all") == 1
        assert cache.entries["eol:all"] == _PRODUCT_INDEX

    @pytest.mark.parametrize(
        "index",
        [
            pytest.param({"index_status": 503}, id="index-unreachable"),
            pytest.param({"index": {"products": []}}, id="index-in-another-shape"),
        ],
    )
    @pytest.mark.asyncio
    async def test_without_the_index_every_candidate_is_looked_up_directly(self, serve, index):
        upstream, _ = serve({"openssl": _OPENSSL}, **index)

        issues = await _issues([_openssl_binary("1.1.1w"), _component("all", "0.0.1", "pkg:npm/all@0.0.1")])

        assert _cycles_of(issues) == {"openssl": "1.1.1"}
        assert upstream.requested.count("all") == 1

    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param(["1.1.1", "3.0"], id="list-of-strings"),
            pytest.param({"cycles": _OPENSSL}, id="object"),
        ],
    )
    @pytest.mark.asyncio
    async def test_a_cycle_payload_in_another_shape_counts_as_no_data(self, serve, payload):
        _, cache = serve({"openssl": payload, "nodejs": _NODEJS})

        issues = await _issues([_openssl_binary("1.1.1w"), _component("node", "16.20.2", "pkg:generic/node@16.20.2")])

        assert _cycles_of(issues) == {"node": "16"}
        assert cache.entries["eol:openssl"] == []


class TestDistroBuilds:
    @pytest.mark.asyncio
    async def test_a_debian_rebuild_is_capped_at_low_and_offers_no_upstream_upgrade(self, serve):
        serve({"nginx": _NGINX})
        purl = "pkg:deb/debian/nginx@1.22.1-9%2Bdeb12u1?arch=amd64&distro=debian-12"

        [issue] = await _issues(
            [_component("nginx", "1.22.1-9+deb12u1", purl, "cpe:2.3:a:nginx:nginx:1.22.1:*:*:*:*:*:*:*")]
        )

        assert issue["severity"] == Severity.LOW.value
        assert issue["distro_build"] is True
        assert "recommended_version" not in issue["eol_info"]

    @pytest.mark.parametrize(
        "component",
        [
            pytest.param(
                _component("nginx", "1.28.3-1~bookworm", "pkg:deb/debian/nginx@1.28.3-1~bookworm?distro=debian-12"),
                id="nginx-org-deb",
            ),
            pytest.param(_component("nginx", "1.28.3", "pkg:generic/nginx@1.28.3"), id="upstream-build"),
        ],
    )
    @pytest.mark.asyncio
    async def test_a_vendor_build_keeps_the_upstream_severity(self, serve, component):
        serve({"nginx": _NGINX})

        [issue] = await _issues([component])

        assert (issue["severity"], issue["distro_build"]) == (Severity.HIGH.value, False)
        assert issue["eol_info"]["recommended_version"] == "1.29.1"


class TestRecommendation:
    @pytest.mark.asyncio
    async def test_the_recommended_upgrade_is_the_newest_supported_cycle(self, serve):
        serve({"nodejs": _NODEJS})

        [issue] = await _issues([_component("node", "16.20.2", "pkg:generic/node@16.20.2")])

        assert (issue["eol_info"]["recommended_cycle"], issue["eol_info"]["recommended_version"]) == ("22", "22.9.0")

    @pytest.mark.asyncio
    async def test_the_cached_cycle_list_stays_as_upstream_sent_it(self, serve):
        _, cache = serve({"nodejs": _NODEJS})

        await _issues([_component("node", "16.20.2", "pkg:generic/node@16.20.2")])

        assert cache.entries["eol:nodejs"] == _NODEJS
        assert all("recommended_version" not in cycle for cycle in cache.entries["eol:nodejs"])


class TestFindings:
    """What the stored finding says, from the analyzer's own output."""

    async def _finding(self, component: dict) -> Any:
        aggregator = ResultAggregator()
        aggregator.aggregate("end_of_life", await analyze_cyclonedx(EndOfLifeAnalyzer(), [component]))
        [finding] = aggregator.get_findings()
        return finding

    @pytest.mark.asyncio
    async def test_a_cycle_without_an_eol_date_reads_as_end_of_life(self, serve):
        serve({"python": _PYTHON})

        finding = await self._finding(_component("python", "2.7.18", "pkg:generic/python@2.7.18"))

        assert finding.description == "End of Life: Version cycle 2.7 reached EOL. Upgrade to 3.13.0 (cycle 3.13)"
        assert finding.details["eol_date"] is True

    @pytest.mark.asyncio
    async def test_a_dated_cycle_names_its_eol_date(self, serve):
        serve({"nodejs": _NODEJS})

        finding = await self._finding(_component("node", "16.20.2", "pkg:generic/node@16.20.2"))

        assert finding.description == (
            f"End of Life: Version cycle 16 reached EOL on {_NODEJS[1]['eol']}. Upgrade to 22.9.0 (cycle 22)"
        )
        assert finding.details["fixed_version"] == "22.9.0"

    @pytest.mark.asyncio
    async def test_without_a_supported_cycle_there_is_no_fixed_version(self, serve):
        serve({"angularjs": _ANGULARJS})

        finding = await self._finding(_component("angular", "1.8.3", "pkg:npm/angular@1.8.3"))

        assert "fixed_version" not in finding.details
        assert finding.description.endswith("Latest: 1.8.3")

    @pytest.mark.asyncio
    async def test_a_distro_rebuild_points_at_the_distribution(self, serve):
        serve({"nginx": _NGINX})
        purl = "pkg:deb/debian/nginx@1.22.1-9%2Bdeb12u1?distro=debian-12"

        finding = await self._finding(_component("nginx", "1.22.1-9+deb12u1", purl))

        assert "distribution" in finding.description
        assert "fixed_version" not in finding.details


def test_the_analyzer_output_carries_no_unread_message():
    issue = EndOfLifeAnalyzer()._create_eol_issue("python", "2.7.18", "python", _PYTHON[1], None, False)
    assert "message" not in issue


class TestCollectProductsToCheck:
    def test_distinct_versions_of_a_product_are_checked_separately(self):
        out = collect_products_to_check(
            [_component("python", "3.8.0"), _component("python", "3.11.0"), _component("python", "3.11.0")]
        )
        assert [version for _, version, _ in out["python"]] == ["3.8.0", "3.11.0"]

    def test_no_components_no_products(self):
        assert collect_products_to_check([]) == {}
