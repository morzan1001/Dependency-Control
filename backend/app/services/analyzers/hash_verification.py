import base64
import logging
from typing import Any, ClassVar

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.constants import ANALYZER_BATCH_SIZES, ANALYZER_TIMEOUTS, NPM_REGISTRY_URL, PYPI_API_URL
from app.core.http_utils import InstrumentedAsyncClient
from app.core.purl import parse_purl
from app.models.finding import Severity
from app.schemas.sbom import has_known_version

from .base import Analyzer
from .deps_dev import fetch_deps_dev_json

logger = logging.getLogger(__name__)


def normalize_hash_algorithm(alg: str | None) -> str:
    return (alg or "").lower().replace("-", "")


class HashVerificationAnalyzer(Analyzer):
    name = "hash_verification"

    # Maven Central omitted: its checksums are served as separate files, not inline.
    REGISTRY_APIS: ClassVar[dict[str, str]] = {
        "pypi": f"{PYPI_API_URL}/{{package}}/{{version}}/json",
        "npm": f"{NPM_REGISTRY_URL}/{{package}}/{{version}}",
    }

    async def analyze(
        self,
        sbom: dict[str, Any],
        settings: dict[str, Any] | None = None,
        *,
        parsed_components: list[dict[str, Any]],
    ) -> dict[str, Any]:
        checks = []
        for component in parsed_components:
            parsed = parse_purl(component.get("purl") or "")
            registry = parsed.registry_system if parsed else None
            name, version, sbom_hashes = component.get("name"), component.get("version", ""), component.get("hashes")
            if registry in self.REGISTRY_APIS and name and has_known_version(version) and sbom_hashes:
                checks.append((CacheKeys.package_hash(registry, name, version), registry, name, version, sbom_hashes))

        registry_hashes, skipped = await self._registry_hashes(
            {key: (registry, name, version) for key, registry, name, version, _ in checks}
        )

        issues = []
        verified_count = 0
        for key, registry, name, version, sbom_hashes in checks:
            outcome = self._compare_hashes(sbom_hashes, registry_hashes.get(key) or {}, name, version, registry)
            if outcome and outcome.get("mismatch"):
                issues.append(outcome)
            elif outcome:
                verified_count += 1

        result: dict[str, Any] = {
            "hash_issues": issues,
            "summary": {
                "verified_count": verified_count,
                "unverifiable_count": len(parsed_components) - verified_count - len(issues),
                "mismatch_count": len(issues),
            },
        }
        if skipped:
            result["partial_components_skipped"] = skipped
        return result

    async def _registry_hashes(self, lookups: dict[str, tuple[str, str, str]]) -> tuple[dict[str, Any], int]:
        async with InstrumentedAsyncClient(
            "Package Registry API", timeout=ANALYZER_TIMEOUTS["hash_verification"]
        ) as client:
            values = await cache_service.get_many_or_fetch(
                lookups,
                lambda key: self._fetch_registry_hashes(client, *lookups[key]),
                CacheTTL.PACKAGE_HASH,
                ANALYZER_BATCH_SIZES["hash_verification"],
            )
        registry_hashes = {key: value for key, value in values.items() if isinstance(value, dict)}
        return registry_hashes, sum(isinstance(value, BaseException) for value in values.values())

    @staticmethod
    def _compare_hashes(
        sbom_hashes: dict[str, str],
        registry_hashes: dict[str, Any],
        name: str,
        version: str,
        registry: str,
    ) -> dict[str, Any] | None:
        for sbom_alg, sbom_value in sbom_hashes.items():
            registry_value = registry_hashes.get(sbom_alg)
            if registry_value is None:
                continue
            # npm serves one digest per algorithm, PyPI one per released file.
            expected_hashes = [registry_value] if isinstance(registry_value, str) else list(registry_value)
            if sbom_value.lower() not in expected_hashes:
                logger.warning(
                    f"HASH MISMATCH: {name}@{version} ({registry}) - "
                    f"SBOM hash does not match registry. Possible tampering!"
                )
                return {
                    "mismatch": True,
                    "component": name,
                    "version": version,
                    "registry": registry,
                    "algorithm": sbom_alg,
                    "sbom_hash": sbom_value,
                    "expected_hashes": expected_hashes,
                    "severity": Severity.CRITICAL.value,
                    "message": "Hash mismatch detected! Package may be tampered.",
                }
            return {"verified": True}
        return None

    async def _fetch_registry_hashes(
        self, client: InstrumentedAsyncClient, registry: str, name: str, version: str
    ) -> dict[str, Any]:
        # npm scopes carry a slash; PyPI names never do.
        url = self.REGISTRY_APIS[registry].format(package=name.replace("/", "%2F"), version=version)
        data = await fetch_deps_dev_json(client, url)
        if data is None:
            return {}
        if registry == "npm":
            return self._parse_npm_dist(data.get("dist", {}), name, version)

        # Every file's digest (sdist plus each platform wheel), so an SBOM built on any platform verifies.
        digests: dict[str, list[str]] = {}
        for url_info in data.get("urls", []):
            for alg, value in url_info.get("digests", {}).items():
                algorithm_digests = digests.setdefault(normalize_hash_algorithm(alg), [])
                if value.lower() not in algorithm_digests:
                    algorithm_digests.append(value.lower())
        return digests

    @staticmethod
    def _parse_npm_dist(dist: dict[str, Any], name: str, version: str) -> dict[str, str]:
        registry_hashes_flat: dict[str, str] = {}
        shasum = dist.get("shasum")
        if shasum:
            registry_hashes_flat["sha1"] = shasum.lower()

        integrity = dist.get("integrity")
        if integrity and integrity.startswith("sha512-"):
            try:
                b64_part = integrity.split("-", 1)[1]
                registry_hashes_flat["sha512"] = base64.b64decode(b64_part).hex()
            except Exception as e:
                logger.warning(f"Failed to decode npm integrity hash for {name}@{version}: {e}")
        return registry_hashes_flat
