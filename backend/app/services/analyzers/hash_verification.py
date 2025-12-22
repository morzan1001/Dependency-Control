"""
Hash Verification Analyzer

Verifies package integrity by comparing SBOM hashes against known-good hashes
from package registries (PyPI, npm, Maven Central, etc.).

Detects:
- Tampered packages (hash mismatch)
- Potentially compromised packages
- Supply chain attacks where package content was modified
"""

import httpx
import asyncio
import hashlib
import logging
from typing import Dict, Any, List, Optional
from .base import Analyzer

logger = logging.getLogger(__name__)


class HashVerificationAnalyzer(Analyzer):
    name = "hash_verification"
    
    # Registry APIs for hash verification
    REGISTRY_APIS = {
        "pypi": "https://pypi.org/pypi/{package}/{version}/json",
        "npm": "https://registry.npmjs.org/{package}/{version}",
        # Maven Central uses a different approach (checksums as separate files)
    }

    async def analyze(self, sbom: Dict[str, Any], settings: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze packages by verifying their hashes against official registries.
        """
        components = self._get_components(sbom)
        issues = []
        verified_count = 0
        unverifiable_count = 0
        
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
        
        return {
            "hash_issues": issues,
            "summary": {
                "verified_count": verified_count,
                "unverifiable_count": unverifiable_count,
                "mismatch_count": len(issues)
            }
        }

    async def _verify_component(self, client: httpx.AsyncClient, component: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Verify a single component's hash against the registry."""
        
        name = component.get("name", "")
        version = component.get("version", "")
        purl = component.get("purl", "")
        
        # Get hashes from SBOM (could be in _hashes from Syft or hashes field)
        sbom_hashes = component.get("_hashes", {}) or component.get("hashes", {})
        
        if not sbom_hashes:
            # No hashes in SBOM to verify
            return None
        
        # Determine registry from PURL
        registry = None
        if purl.startswith("pkg:pypi/"):
            registry = "pypi"
        elif purl.startswith("pkg:npm/"):
            registry = "npm"
        else:
            # Other registries not yet supported
            return None
        
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
        sbom_hashes: Dict[str, str]
    ) -> Optional[Dict[str, Any]]:
        """Verify package hash against PyPI."""
        
        url = self.REGISTRY_APIS["pypi"].format(package=name, version=version)
        response = await client.get(url)
        
        if response.status_code != 200:
            return None
        
        data = response.json()
        
        # PyPI provides hashes in urls[].digests
        registry_hashes = {}
        for url_info in data.get("urls", []):
            digests = url_info.get("digests", {})
            for alg, value in digests.items():
                # Normalize algorithm names
                alg_lower = alg.lower().replace("-", "")
                if alg_lower not in registry_hashes:
                    registry_hashes[alg_lower] = set()
                registry_hashes[alg_lower].add(value.lower())
        
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
                        "message": f"Hash mismatch detected! Package may be tampered."
                    }
                else:
                    return {"verified": True}
        
        return None

    async def _verify_npm(
        self, 
        client: httpx.AsyncClient, 
        name: str, 
        version: str, 
        sbom_hashes: Dict[str, str]
    ) -> Optional[Dict[str, Any]]:
        """Verify package hash against npm registry."""
        
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
        
        if dist.get("shasum"):
            registry_hashes["sha1"] = {dist["shasum"].lower()}
        
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
                except Exception:
                    pass
        
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
                        "message": f"Hash mismatch detected! Package may be tampered."
                    }
                else:
                    return {"verified": True}
        
        return None
