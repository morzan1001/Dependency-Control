"""The OSV analyzer's real HTTP client, answered in-process through httpx.MockTransport."""

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from app.core.http_utils import InstrumentedAsyncClient
from app.services.analyzers.osv import OSVAnalyzer


def serve_osv(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
) -> list[httpx.Request]:
    """Answer every OSV request with ``handler``, backoff delays zeroed; returns the requests in arrival order."""
    seen: list[httpx.Request] = []

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    transport = httpx.MockTransport(_record)
    monkeypatch.setattr(OSVAnalyzer, "retry_base_delay", 0.0)
    monkeypatch.setattr(
        "app.services.analyzers.osv.InstrumentedAsyncClient",
        lambda service, **kwargs: InstrumentedAsyncClient(service, transport=transport, **kwargs),
    )
    return seen


def osv_cache(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """An in-memory cache_service for the OSV analyzer; the returned dict is its store."""
    store: dict[str, Any] = {}

    async def _mget(keys: list[str]) -> dict[str, Any]:
        return {key: store.get(key) for key in keys}

    async def _mset(mapping: dict[str, Any], ttl_seconds: int | None = None) -> bool:
        store.update(mapping)
        return True

    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mget", _mget)
    monkeypatch.setattr("app.services.analyzers.osv.cache_service.mset", _mset)
    return store


def batch_queries(requests: list[httpx.Request]) -> list[dict[str, Any]]:
    """Every querybatch query among ``requests``, in the order they were sent."""
    return [
        query for request in requests if request.method == "POST" for query in json.loads(request.content)["queries"]
    ]


def vuln_ids_fetched(requests: list[httpx.Request]) -> list[str]:
    return [request.url.path.rsplit("/", 1)[-1] for request in requests if request.method == "GET"]


# Records as GET /v1/vulns/{id} serves them, trimmed to the fields the analyzer reads.
def _ranges(*events: dict[str, str], kind: str = "ECOSYSTEM") -> list[dict[str, Any]]:
    return [{"type": kind, "events": list(events)}]


# One affected entry per maintained Django release line.
DJANGO_REDOS: dict[str, Any] = {
    "id": "GHSA-vm8q-m57g-pff3",
    "summary": "Regular expression denial-of-service in Django",
    "details": "In Django 3.2 before 3.2.25, 4.2 before 4.2.11, and 5.0 before 5.0.3, ...",
    "aliases": ["BIT-django-2024-27351", "CVE-2024-27351", "PYSEC-2024-47"],
    "published": "2024-03-15T21:30:43Z",
    "modified": "2026-09-10T03:50:10.784705170Z",
    "database_specific": {"severity": "MODERATE"},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H"}],
    "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-27351"}],
    "affected": [
        {
            "package": {"name": "django", "ecosystem": "PyPI", "purl": "pkg:pypi/django"},
            "ranges": _ranges({"introduced": lower}, {"fixed": fixed}),
        }
        for lower, fixed in (("3.2", "3.2.25"), ("4.2", "4.2.11"), ("5.0", "5.0.3"))
    ],
}

# The GIT range comes first and its fix is a commit hash.
URLLIB3_CRLF: dict[str, Any] = {
    "id": "PYSEC-2020-148",
    "details": "urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP request method, ...",
    "aliases": ["CVE-2020-26137", "GHSA-wqvq-5m8c-6g24"],
    "affected": [
        {
            "package": {"name": "urllib3", "ecosystem": "PyPI", "purl": "pkg:pypi/urllib3"},
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/urllib3/urllib3",
                    "events": [{"introduced": "0"}, {"fixed": "1dd69c5c5982fae7c87a620d487c2ebf7a6b436b"}],
                },
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.25.9"}]},
            ],
        }
    ],
}

# request is never fixed; only its fork @cypress/request is.
REQUEST_SSRF: dict[str, Any] = {
    "id": "GHSA-p8p7-x288-28g6",
    "summary": "Server-Side Request Forgery in Request",
    "database_specific": {"severity": "MODERATE"},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
    "affected": [
        {
            "package": {"name": "request", "ecosystem": "npm", "purl": "pkg:npm/request"},
            "ranges": _ranges({"introduced": "0"}, {"last_affected": "2.88.2"}, kind="SEMVER"),
        },
        {
            "package": {"name": "@cypress/request", "ecosystem": "npm", "purl": "pkg:npm/%40cypress/request"},
            "ranges": _ranges({"introduced": "0"}, {"fixed": "3.0.0"}, kind="SEMVER"),
        },
    ],
}

# Two Go modules, each with its own vulnerable symbols; stdlib has two release lines in one range.
GO_RAPID_RESET: dict[str, Any] = {
    "id": "GO-2023-2102",
    "summary": "HTTP/2 rapid reset can cause excessive work in net/http",
    "aliases": ["BIT-golang-2023-39325", "CVE-2023-39325", "GHSA-4374-p667-p6c8"],
    "affected": [
        {
            "package": {"name": "stdlib", "ecosystem": "Go", "purl": "pkg:golang/stdlib"},
            "ranges": _ranges(
                {"introduced": "0"},
                {"fixed": "1.20.10"},
                {"introduced": "1.21.0-0"},
                {"fixed": "1.21.3"},
                kind="SEMVER",
            ),
            "ecosystem_specific": {
                "imports": [
                    {"path": "net/http", "symbols": ["ListenAndServe", "Server.Serve", "http2Server.ServeConn"]}
                ]
            },
        },
        {
            "package": {"name": "golang.org/x/net", "ecosystem": "Go", "purl": "pkg:golang/golang.org/x/net"},
            "ranges": _ranges({"introduced": "0"}, {"fixed": "0.17.0"}, kind="SEMVER"),
            "ecosystem_specific": {
                "imports": [{"path": "golang.org/x/net/http2", "symbols": ["Server.ServeConn", "serverConn.serve"]}]
            },
        },
    ],
}

# Maven names are group:artifact; a second group ships an artifact of the same name, never fixed.
LOG4SHELL: dict[str, Any] = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "summary": "Remote code injection in Log4j",
    "affected": [
        {
            "package": {
                "name": "org.apache.logging.log4j:log4j-core",
                "ecosystem": "Maven",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core",
            },
            "ranges": _ranges({"introduced": lower}, {"fixed": fixed}),
        }
        for lower, fixed in (("2.13.0", "2.15.0"), ("2.4", "2.12.2"))
    ]
    + [
        {
            "package": {
                "name": "com.guicedee.services:log4j-core",
                "ecosystem": "Maven",
                "purl": "pkg:maven/com.guicedee.services/log4j-core",
            },
            "ranges": _ranges({"introduced": "0"}, {"last_affected": "1.2.1.2-jre17"}),
        }
    ],
}

# Every Alpine release shares one source purl but has its own fix; the record has no summary.
ALPINE_OPENSSL: dict[str, Any] = {
    "id": "ALPINE-CVE-2023-5678",
    "details": "Issue summary: Generating excessively long X9.42 DH keys ... may be very slow.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
    "affected": [
        {
            "package": {
                "name": "openssl",
                "ecosystem": f"Alpine:{release}",
                "purl": "pkg:apk/alpine/openssl?arch=source",
            },
            "ranges": _ranges({"introduced": "1.0.2"}, {"fixed": fixed}),
            "ecosystem_specific": {},
        }
        for release, fixed in (("v3.16", "1.1.1w-r1"), ("v3.17", "3.0.12-r1"), ("v3.18", "3.1.4-r1"))
    ],
}

DEBIAN_OPENSSL: dict[str, Any] = {
    "id": "DEBIAN-CVE-2023-5678",
    "details": "Issue summary: Generating excessively long X9.42 DH keys ... may be very slow.",
    "affected": [
        {
            "package": {
                "name": "openssl",
                "ecosystem": f"Debian:{release}",
                "purl": f"pkg:deb/debian/openssl?arch=source&distro={codename}",
            },
            "ranges": _ranges({"introduced": "0"}, {"fixed": fixed}),
            "ecosystem_specific": {"urgency": "not yet assigned"},
        }
        for release, codename, fixed in (("12", "bookworm", "3.0.13-1~deb12u1"), ("13", "trixie", "3.0.12-2"))
    ],
}

# Every Ubuntu release and its Pro archive share one source purl; only the listed versions tell them apart.
UBUNTU_OPENSSL: dict[str, Any] = {
    "id": "UBUNTU-CVE-2025-68160",
    "details": "Issue summary: Writing large, newline-free data into a BIO chain ... out-of-bounds write.",
    "modified": "2026-10-05T19:21:43.551395441Z",
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H"},
        {"type": "Ubuntu", "score": "low"},
    ],
    "affected": [
        {
            "package": {
                "name": "openssl",
                "ecosystem": ecosystem,
                "purl": f"pkg:deb/ubuntu/openssl?arch=source&distro={archive}",
            },
            "ranges": _ranges({"introduced": "0"}, {"fixed": fixed}),
            "versions": versions,
        }
        for ecosystem, archive, fixed, versions in (
            (
                "Ubuntu:Pro:18.04:LTS",
                "esm-infra%2Fbionic",
                "1.1.1-1ubuntu2.1~18.04.23+esm7",
                ["1.1.1-1ubuntu2.1~18.04.23", "1.1.1-1ubuntu2.1~18.04.23+esm6"],
            ),
            (
                "Ubuntu:Pro:20.04:LTS",
                "esm-infra%2Ffocal",
                "1.1.1f-1ubuntu2.24+esm2",
                ["1.1.1f-1ubuntu2.23", "1.1.1f-1ubuntu2.24", "1.1.1f-1ubuntu2.24+esm1"],
            ),
            ("Ubuntu:22.04:LTS", "jammy", "3.0.2-0ubuntu1.21", ["3.0.2-0ubuntu1.19", "3.0.2-0ubuntu1.20"]),
        )
    ],
}

MALWARE_COMBINEZONE: dict[str, Any] = {
    "id": "MAL-2024-2000",
    "summary": "Malicious code in combinezone (npm)",
    "details": "\n---\n_-= Per source details. Do not edit below this line.=-_\n",
    "aliases": ["SNYK-JS-COMBINEZONE-5406398"],
    "modified": "2024-10-24T01:01:55Z",
    "published": "2024-06-25T12:34:05Z",
    "references": [{"type": "ADVISORY", "url": "https://security.snyk.io/vuln/SNYK-JS-COMBINEZONE-5406398"}],
    "affected": [
        {"package": {"name": "combinezone", "ecosystem": "npm", "purl": "pkg:npm/combinezone"}, "versions": ["7.14.2"]}
    ],
}
