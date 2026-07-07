"""
Hash Verification Analyzer

Verifies package integrity by comparing SBOM hashes against known-good hashes
from package registries (PyPI, npm, Maven Central, etc.).

Detects:
- Tampered packages (hash mismatch)
- Potentially compromised packages
- Supply chain attacks where package content was modified
"""

import asyncio
import base64
import logging
from typing import Any, Dict, List, Optional

import httpx

from app.core.cache import CacheKeys, CacheTTL, cache_service
from app.core.http_utils import InstrumentedAsyncClient
from app.core.constants import ANALYZER_TIMEOUTS, NPM_REGISTRY_URL, PYPI_API_URL
from app.models.finding import Severity

from .base import Analyzer
from .purl_utils import is_npm, is_pypi, normalize_hash_algorithm

logger = logging.getLogger(__name__)


class HashVerificationAnalyzer(Analyzer):
    name = "hash_verification"

    # Registry APIs for hash verification
    REGISTRY_APIS = {
        "pypi": f"{PYPI_API_URL}/{{package}}/{{version}}/json",
        "npm": f"{NPM_REGISTRY_URL}/{{package}}/{{version}}",
        # Maven Central uses a different approach (checksums as separate files)
    }

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Optional[Dict[str, Any]] = None,
        parsed_components: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze packages by verifying their hashes against official registries.

        If SBOM contains hashes: verifies them against registry
        If SBOM has no hashes: fetches hashes from registry for enrichment
        """
        components = self._get_components(sbom, parsed_components)
        issues = []
        verified_count = 0
        unverifiable_count = 0
        no_hash_in_sbom_count = 0
        fetched_hashes = {}  # package@version -> {alg: hash}
        timeout = ANALYZER_TIMEOUTS.get("hash_verification", ANALYZER_TIMEOUTS["default"])

        async with InstrumentedAsyncClient("Package Registry API", timeout=timeout) as client:
            tasks = []
            for component in components:
                tasks.append(self._verify_component(client, component))

            results = await asyncio.gather(*tasks)

            for result in results:
                if result is None:
                    unverifiable_count += 1
                elif result.get("verified"):
                    verified_count += 1
                elif result.get("mismatch"):
                    issues.append(result)
                elif result.get("fetched_hashes"):
                    # We fetched hashes from registry (no hash in SBOM)
                    no_hash_in_sbom_count += 1
                    key = f"{result['component']}@{result['version']}"
                    fetched_hashes[key] = result["fetched_hashes"]

        return {
            "hash_issues": issues,
            "fetched_hashes": fetched_hashes,  # For enrichment
            "summary": {
                "verified_count": verified_count,
                "unverifiable_count": unverifiable_count,
                "mismatch_count": len(issues),
                "no_hash_in_sbom": no_hash_in_sbom_count,
                "hashes_fetched": len(fetched_hashes),
            },
        }

    @staticmethod
    def _detect_registry(purl: str) -> Optional[str]:
        """Return the registry name for a PURL, or None if unsupported."""
        if is_pypi(purl):
            return "pypi"
        if is_npm(purl):
            return "npm"
        return None

    @staticmethod
    def _hashes_from_cyclonedx_list(hashes: List[Any]) -> Dict[str, str]:
        """Extract hashes from a CycloneDX-style list."""
        result: Dict[str, str] = {}
        for h in hashes:
            if not isinstance(h, dict):
                continue
            alg_value = h.get("alg")
            content_value = h.get("content")
            if isinstance(alg_value, str) and isinstance(content_value, str):
                result[normalize_hash_algorithm(alg_value)] = content_value
        return result

    @staticmethod
    def _extract_sbom_hashes(component: Dict[str, Any]) -> Dict[str, str]:
        """Extract hashes from a component, supporting Syft/CycloneDX/normalized formats."""
        sbom_hashes: Dict[str, str] = {}
        syft_hashes = component.get("_hashes")
        component_hashes = component.get("hashes")

        if isinstance(syft_hashes, dict) and syft_hashes:
            sbom_hashes = dict(syft_hashes)
        elif isinstance(component_hashes, list) and component_hashes:
            sbom_hashes = HashVerificationAnalyzer._hashes_from_cyclonedx_list(component_hashes)
        elif isinstance(component_hashes, dict) and component_hashes:
            sbom_hashes = dict(component_hashes)

        for ext_ref in component.get("externalReferences", []):
            for h in ext_ref.get("hashes", []) or []:
                if isinstance(h, dict) and h.get("alg") and h.get("content"):
                    alg = normalize_hash_algorithm(h["alg"])
                    if alg not in sbom_hashes:
                        sbom_hashes[alg] = h["content"]

        return sbom_hashes

    async def _verify_component(
        self, client: InstrumentedAsyncClient, component: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Verify a single component's hash against the registry."""

        name = component.get("name", "")
        version = component.get("version", "")
        purl = component.get("purl", "")

        if not name or not version:
            return None

        registry = self._detect_registry(purl)
        if registry is None:
            return None

        sbom_hashes = self._extract_sbom_hashes(component)

        try:
            if registry == "pypi":
                return await self._verify_pypi(client, name, version, sbom_hashes)
            if registry == "npm":
                return await self._verify_npm(client, name, version, sbom_hashes)
        except Exception as e:
            logger.debug(f"Hash verification failed for {name}@{version}: {e}")
            return None

        return None

    @staticmethod
    def _compare_hashes(
        sbom_hashes: Dict[str, str],
        registry_hashes: Dict[str, set],
        name: str,
        version: str,
        registry: str,
    ) -> Optional[Dict[str, Any]]:
        """Compare SBOM hashes to registry hashes; return mismatch/verified/None."""
        for sbom_alg, sbom_value in sbom_hashes.items():
            sbom_alg_normalized = normalize_hash_algorithm(sbom_alg)
            if sbom_alg_normalized not in registry_hashes:
                continue
            if sbom_value.lower() not in registry_hashes[sbom_alg_normalized]:
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
                    "expected_hashes": list(registry_hashes[sbom_alg_normalized]),
                    "severity": Severity.CRITICAL.value,
                    "message": "Hash mismatch detected! Package may be tampered.",
                }
            return {"verified": True}
        return None

    @staticmethod
    def _evaluate_registry_hashes(
        registry_hashes_flat: Optional[Dict[str, Any]],
        sbom_hashes: Dict[str, str],
        name: str,
        version: str,
        registry: str,
    ) -> Optional[Dict[str, Any]]:
        """Convert flat registry hashes and either enrich or compare against SBOM."""
        if registry_hashes_flat is None or not registry_hashes_flat:
            return None

        # A registry value may be a single digest (npm: one dist per version)
        # or a list of digests (PyPI: one entry per released file). Normalize
        # both into a set so _compare_hashes accepts any legitimate file hash.
        registry_hashes: Dict[str, set] = {}
        for k, v in registry_hashes_flat.items():
            registry_hashes[k] = set(v) if isinstance(v, (list, tuple, set)) else {v}

        if not sbom_hashes:
            return {
                "fetched_hashes": registry_hashes_flat,
                "component": name,
                "version": version,
                "registry": registry,
            }

        return HashVerificationAnalyzer._compare_hashes(sbom_hashes, registry_hashes, name, version, registry)

    async def _fetch_pypi_registry_hashes(
        self, client: InstrumentedAsyncClient, name: str, version: str
    ) -> Optional[Dict[str, List[str]]]:
        """Fetch PyPI registry hashes; empty dict = negative cache, None = transient error.

        A released version ships one entry per file in ``data['urls']`` (sdist
        plus one wheel per platform), each with its own digest. Collect EVERY
        file's digest per algorithm so an SBOM built on any platform verifies
        against the matching wheel rather than only the first ``urls`` entry.
        """
        try:
            url = self.REGISTRY_APIS["pypi"].format(package=name, version=version)
            response = await client.get(url)
            if response.status_code != 200:
                return {}

            data = response.json()
            registry_hashes_flat: Dict[str, List[str]] = {}
            for url_info in data.get("urls", []):
                for alg, value in url_info.get("digests", {}).items():
                    alg_normalized = normalize_hash_algorithm(alg)
                    digest = value.lower()
                    digests = registry_hashes_flat.setdefault(alg_normalized, [])
                    if digest not in digests:
                        digests.append(digest)
            return registry_hashes_flat or {}
        except httpx.TimeoutException:
            logger.debug(f"PyPI API timeout for {name}@{version}")
            return None
        except httpx.ConnectError:
            logger.debug(f"PyPI API connection error for {name}@{version}")
            return None
        except Exception as e:
            logger.debug(f"PyPI hash fetch failed for {name}@{version}: {e}")
            return None

    async def _verify_pypi(
        self,
        client: InstrumentedAsyncClient,
        name: str,
        version: str,
        sbom_hashes: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Verify package hash against PyPI, or fetch hashes if none in SBOM."""

        cache_key = CacheKeys.package_hash("pypi", name, version)

        async def fetch_pypi_hashes() -> Optional[Dict[str, List[str]]]:
            return await self._fetch_pypi_registry_hashes(client, name, version)

        registry_hashes_flat = await cache_service.get_or_fetch_with_lock(
            key=cache_key,
            fetch_fn=fetch_pypi_hashes,
            ttl_seconds=CacheTTL.PACKAGE_HASH,
        )

        return self._evaluate_registry_hashes(registry_hashes_flat, sbom_hashes, name, version, "pypi")

    @staticmethod
    def _parse_npm_dist(dist: Dict[str, Any], name: str, version: str) -> Dict[str, str]:
        """Parse the npm dist payload into a flat hash dictionary."""
        registry_hashes_flat: Dict[str, str] = {}
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

    async def _fetch_npm_registry_hashes(
        self, client: InstrumentedAsyncClient, name: str, version: str
    ) -> Optional[Dict[str, str]]:
        """Fetch npm registry hashes; empty dict = negative cache, None = transient error."""
        try:
            encoded_name = name.replace("/", "%2F") if "/" in name else name
            url = self.REGISTRY_APIS["npm"].format(package=encoded_name, version=version)
            response = await client.get(url)
            if response.status_code != 200:
                return {}

            data = response.json()
            registry_hashes_flat = self._parse_npm_dist(data.get("dist", {}), name, version)
            return registry_hashes_flat or {}
        except httpx.TimeoutException:
            logger.debug(f"npm API timeout for {name}@{version}")
            return None
        except httpx.ConnectError:
            logger.debug(f"npm API connection error for {name}@{version}")
            return None
        except Exception as e:
            logger.debug(f"npm hash fetch failed for {name}@{version}: {e}")
            return None

    async def _verify_npm(
        self,
        client: InstrumentedAsyncClient,
        name: str,
        version: str,
        sbom_hashes: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Verify package hash against npm registry, or fetch hashes if none in SBOM."""

        cache_key = CacheKeys.package_hash("npm", name, version)

        async def fetch_npm_hashes() -> Optional[Dict[str, str]]:
            return await self._fetch_npm_registry_hashes(client, name, version)

        registry_hashes_flat = await cache_service.get_or_fetch_with_lock(
            key=cache_key,
            fetch_fn=fetch_npm_hashes,
            ttl_seconds=CacheTTL.PACKAGE_HASH,
        )

        return self._evaluate_registry_hashes(registry_hashes_flat, sbom_hashes, name, version, "npm")
