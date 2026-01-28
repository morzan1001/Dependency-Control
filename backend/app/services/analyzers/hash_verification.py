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
        timeout = ANALYZER_TIMEOUTS.get(
            "hash_verification", ANALYZER_TIMEOUTS["default"]
        )

        async with httpx.AsyncClient(timeout=timeout) as client:
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

    async def _verify_component(
        self, client: httpx.AsyncClient, component: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Verify a single component's hash against the registry."""

        name = component.get("name", "")
        version = component.get("version", "")
        purl = component.get("purl", "")

        if not name or not version:
            return None

        # Determine registry from PURL using centralized utils
        registry = None
        if is_pypi(purl):
            registry = "pypi"
        elif is_npm(purl):
            registry = "npm"
        else:
            # Other registries not yet supported
            return None

        # Get hashes from SBOM - handle multiple formats:
        # 1. CycloneDX: "hashes": [{"alg": "SHA-256", "content": "..."}]
        # 2. Syft: "_hashes": {"sha256": "..."}
        # 3. Already normalized: "hashes": {"sha256": "..."}
        sbom_hashes = {}

        # Check for Syft-style _hashes (dict)
        if component.get("_hashes") and isinstance(component.get("_hashes"), dict):
            sbom_hashes = component["_hashes"]

        # Check for CycloneDX-style hashes (list of {alg, content})
        elif component.get("hashes") and isinstance(component.get("hashes"), list):
            for h in component["hashes"]:
                if isinstance(h, dict) and h.get("alg") and h.get("content"):
                    alg_value = h["alg"]
                    content_value = h["content"]
                    # Validate types before processing
                    if isinstance(alg_value, str) and isinstance(content_value, str):
                        alg = normalize_hash_algorithm(alg_value)
                        sbom_hashes[alg] = content_value

        # Check for already normalized dict hashes
        elif component.get("hashes") and isinstance(component.get("hashes"), dict):
            sbom_hashes = component["hashes"]

        # Also check externalReferences for download URLs with hashes
        for ext_ref in component.get("externalReferences", []):
            if ext_ref.get("hashes"):
                for h in ext_ref["hashes"]:
                    if isinstance(h, dict) and h.get("alg") and h.get("content"):
                        alg = normalize_hash_algorithm(h["alg"])
                        if alg not in sbom_hashes:
                            sbom_hashes[alg] = h["content"]

        try:
            if registry == "pypi":
                return await self._verify_pypi(client, name, version, sbom_hashes)
            elif registry == "npm":
                return await self._verify_npm(client, name, version, sbom_hashes)
        except Exception as e:
            logger.debug(f"Hash verification failed for {name}@{version}: {e}")
            return None

        return None

    async def _verify_pypi(
        self,
        client: httpx.AsyncClient,
        name: str,
        version: str,
        sbom_hashes: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Verify package hash against PyPI, or fetch hashes if none in SBOM."""

        cache_key = CacheKeys.package_hash("pypi", name, version)

        async def fetch_pypi_hashes() -> Optional[Dict[str, str]]:
            """Fetch hashes from PyPI API."""
            try:
                url = self.REGISTRY_APIS["pypi"].format(package=name, version=version)
                response = await client.get(url)

                if response.status_code != 200:
                    return {}  # Empty dict = negative cache

                data = response.json()
                registry_hashes_flat: Dict[str, str] = {}

                for url_info in data.get("urls", []):
                    digests = url_info.get("digests", {})
                    for alg, value in digests.items():
                        alg_normalized = normalize_hash_algorithm(alg)
                        if alg_normalized not in registry_hashes_flat:
                            registry_hashes_flat[alg_normalized] = value.lower()

                return registry_hashes_flat if registry_hashes_flat else {}
            except httpx.TimeoutException:
                logger.debug(f"PyPI API timeout for {name}@{version}")
                return None
            except httpx.ConnectError:
                logger.debug(f"PyPI API connection error for {name}@{version}")
                return None
            except Exception as e:
                logger.debug(f"PyPI hash fetch failed for {name}@{version}: {e}")
                return None

        # Use locked fetch to prevent multiple pods fetching same package
        registry_hashes_flat = await cache_service.get_or_fetch_with_lock(
            key=cache_key,
            fetch_fn=fetch_pypi_hashes,
            ttl_seconds=CacheTTL.PACKAGE_HASH,
        )

        if registry_hashes_flat is None or not registry_hashes_flat:
            return None

        # Convert flat dict to set-based for comparison
        registry_hashes = {k: {v} for k, v in registry_hashes_flat.items()}

        # If no hashes in SBOM, return fetched hashes for enrichment
        if not sbom_hashes:
            return {
                "fetched_hashes": registry_hashes_flat,
                "component": name,
                "version": version,
                "registry": "pypi",
            }

        # Compare with SBOM hashes
        for sbom_alg, sbom_value in sbom_hashes.items():
            sbom_alg_normalized = normalize_hash_algorithm(sbom_alg)
            sbom_value_lower = sbom_value.lower()

            if sbom_alg_normalized in registry_hashes:
                if sbom_value_lower not in registry_hashes[sbom_alg_normalized]:
                    # Hash mismatch - security concern!
                    logger.warning(
                        f"HASH MISMATCH: {name}@{version} (pypi) - "
                        f"SBOM hash does not match registry. Possible tampering!"
                    )
                    return {
                        "mismatch": True,
                        "component": name,
                        "version": version,
                        "registry": "pypi",
                        "algorithm": sbom_alg,
                        "sbom_hash": sbom_value,
                        "expected_hashes": list(registry_hashes[sbom_alg_normalized]),
                        "severity": Severity.CRITICAL.value,
                        "message": "Hash mismatch detected! Package may be tampered.",
                    }
                else:
                    return {"verified": True}

        return None

    async def _verify_npm(
        self,
        client: httpx.AsyncClient,
        name: str,
        version: str,
        sbom_hashes: Dict[str, str],
    ) -> Optional[Dict[str, Any]]:
        """Verify package hash against npm registry, or fetch hashes if none in SBOM."""

        cache_key = CacheKeys.package_hash("npm", name, version)

        async def fetch_npm_hashes() -> Optional[Dict[str, str]]:
            """Fetch hashes from npm registry."""
            try:
                encoded_name = name.replace("/", "%2F") if "/" in name else name
                url = self.REGISTRY_APIS["npm"].format(
                    package=encoded_name, version=version
                )
                response = await client.get(url)

                if response.status_code != 200:
                    return {}  # Empty dict = negative cache

                data = response.json()
                dist = data.get("dist", {})
                registry_hashes_flat: Dict[str, str] = {}

                if dist.get("shasum"):
                    registry_hashes_flat["sha1"] = dist["shasum"].lower()

                if dist.get("integrity"):
                    integrity = dist["integrity"]
                    if integrity.startswith("sha512-"):
                        try:
                            b64_part = integrity.split("-", 1)[1]
                            hex_value = base64.b64decode(b64_part).hex()
                            registry_hashes_flat["sha512"] = hex_value
                        except Exception as e:
                            logger.warning(
                                f"Failed to decode npm integrity hash for {name}@{version}: {e}"
                            )

                return registry_hashes_flat if registry_hashes_flat else {}
            except httpx.TimeoutException:
                logger.debug(f"npm API timeout for {name}@{version}")
                return None
            except httpx.ConnectError:
                logger.debug(f"npm API connection error for {name}@{version}")
                return None
            except Exception as e:
                logger.debug(f"npm hash fetch failed for {name}@{version}: {e}")
                return None

        # Use locked fetch to prevent multiple pods fetching same package
        registry_hashes_flat = await cache_service.get_or_fetch_with_lock(
            key=cache_key,
            fetch_fn=fetch_npm_hashes,
            ttl_seconds=CacheTTL.PACKAGE_HASH,
        )

        if registry_hashes_flat is None or not registry_hashes_flat:
            return None

        # Convert flat dict to set-based for comparison
        registry_hashes = {k: {v} for k, v in registry_hashes_flat.items()}

        # If no hashes in SBOM, return fetched hashes for enrichment
        if not sbom_hashes:
            return {
                "fetched_hashes": registry_hashes_flat,
                "component": name,
                "version": version,
                "registry": "npm",
            }

        # Compare with SBOM hashes
        for sbom_alg, sbom_value in sbom_hashes.items():
            sbom_alg_normalized = normalize_hash_algorithm(sbom_alg)
            sbom_value_lower = sbom_value.lower()

            if sbom_alg_normalized in registry_hashes:
                if sbom_value_lower not in registry_hashes[sbom_alg_normalized]:
                    # Hash mismatch - security concern!
                    logger.warning(
                        f"HASH MISMATCH: {name}@{version} (npm) - "
                        f"SBOM hash does not match registry. Possible tampering!"
                    )
                    return {
                        "mismatch": True,
                        "component": name,
                        "version": version,
                        "registry": "npm",
                        "algorithm": sbom_alg,
                        "sbom_hash": sbom_value,
                        "expected_hashes": list(registry_hashes[sbom_alg_normalized]),
                        "severity": Severity.CRITICAL.value,
                        "message": "Hash mismatch detected! Package may be tampered.",
                    }
                else:
                    return {"verified": True}

        return None
