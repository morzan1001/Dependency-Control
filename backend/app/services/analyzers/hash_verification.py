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
import hashlib
import logging
from typing import Any, Dict, List, Optional

import httpx

from .base import Analyzer
from .purl_utils import is_pypi, is_npm, get_registry_system

logger = logging.getLogger(__name__)


class HashVerificationAnalyzer(Analyzer):
    name = "hash_verification"

    # Registry APIs for hash verification
    REGISTRY_APIS = {
        "pypi": "https://pypi.org/pypi/{package}/{version}/json",
        "npm": "https://registry.npmjs.org/{package}/{version}",
        # Maven Central uses a different approach (checksums as separate files)
    }

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Dict[str, Any] = None,
        parsed_components: List[Dict[str, Any]] = None,
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

        async with httpx.AsyncClient(timeout=10.0) as client:
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
                    # Normalize algorithm name: "SHA-256" -> "sha256"
                    alg = h["alg"].lower().replace("-", "")
                    sbom_hashes[alg] = h["content"]

        # Check for already normalized dict hashes
        elif component.get("hashes") and isinstance(component.get("hashes"), dict):
            sbom_hashes = component["hashes"]

        # Also check externalReferences for download URLs with hashes
        for ext_ref in component.get("externalReferences", []):
            if ext_ref.get("hashes"):
                for h in ext_ref["hashes"]:
                    if isinstance(h, dict) and h.get("alg") and h.get("content"):
                        alg = h["alg"].lower().replace("-", "")
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

        url = self.REGISTRY_APIS["pypi"].format(package=name, version=version)
        response = await client.get(url)

        if response.status_code != 200:
            return None

        data = response.json()

        # PyPI provides hashes in urls[].digests
        registry_hashes = {}
        registry_hashes_flat = {}  # For returning fetched hashes

        for url_info in data.get("urls", []):
            digests = url_info.get("digests", {})
            for alg, value in digests.items():
                # Normalize algorithm names
                alg_lower = alg.lower().replace("-", "")
                if alg_lower not in registry_hashes:
                    registry_hashes[alg_lower] = set()
                registry_hashes[alg_lower].add(value.lower())

                # Store first hash of each type for enrichment
                if alg_lower not in registry_hashes_flat:
                    registry_hashes_flat[alg_lower] = value.lower()

        # If no hashes in SBOM, return fetched hashes for enrichment
        if not sbom_hashes:
            if registry_hashes_flat:
                return {
                    "fetched_hashes": registry_hashes_flat,
                    "component": name,
                    "version": version,
                    "registry": "pypi",
                }
            return None

        # Compare with SBOM hashes
        for sbom_alg, sbom_value in sbom_hashes.items():
            sbom_alg_normalized = sbom_alg.lower().replace("-", "")
            sbom_value_lower = sbom_value.lower()

            if sbom_alg_normalized in registry_hashes:
                if sbom_value_lower not in registry_hashes[sbom_alg_normalized]:
                    # Hash mismatch!
                    return {
                        "mismatch": True,
                        "component": name,
                        "version": version,
                        "registry": "pypi",
                        "algorithm": sbom_alg,
                        "sbom_hash": sbom_value,
                        "expected_hashes": list(registry_hashes[sbom_alg_normalized]),
                        "severity": "CRITICAL",
                        "message": f"Hash mismatch detected! Package may be tampered.",
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

        # Handle scoped packages
        encoded_name = name.replace("/", "%2F") if "/" in name else name
        url = self.REGISTRY_APIS["npm"].format(package=encoded_name, version=version)
        response = await client.get(url)

        if response.status_code != 200:
            return None

        data = response.json()

        # npm provides shasum (SHA1) and integrity (SHA512)
        dist = data.get("dist", {})
        registry_hashes = {}
        registry_hashes_flat = {}

        if dist.get("shasum"):
            registry_hashes["sha1"] = {dist["shasum"].lower()}
            registry_hashes_flat["sha1"] = dist["shasum"].lower()

        if dist.get("integrity"):
            # Format: sha512-base64encoded...
            integrity = dist["integrity"]
            if integrity.startswith("sha512-"):
                # Convert base64 to hex for comparison
                import base64

                try:
                    b64_part = integrity.split("-", 1)[1]
                    hex_value = base64.b64decode(b64_part).hex()
                    registry_hashes["sha512"] = {hex_value}
                    registry_hashes_flat["sha512"] = hex_value
                except Exception:
                    pass

        # If no hashes in SBOM, return fetched hashes for enrichment
        if not sbom_hashes:
            if registry_hashes_flat:
                return {
                    "fetched_hashes": registry_hashes_flat,
                    "component": name,
                    "version": version,
                    "registry": "npm",
                }
            return None

        # Compare with SBOM hashes
        for sbom_alg, sbom_value in sbom_hashes.items():
            sbom_alg_normalized = sbom_alg.lower().replace("-", "")
            sbom_value_lower = sbom_value.lower()

            if sbom_alg_normalized in registry_hashes:
                if sbom_value_lower not in registry_hashes[sbom_alg_normalized]:
                    return {
                        "mismatch": True,
                        "component": name,
                        "version": version,
                        "registry": "npm",
                        "algorithm": sbom_alg,
                        "sbom_hash": sbom_value,
                        "expected_hashes": list(registry_hashes[sbom_alg_normalized]),
                        "severity": "CRITICAL",
                        "message": f"Hash mismatch detected! Package may be tampered.",
                    }
                else:
                    return {"verified": True}

        return None
