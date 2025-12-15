import httpx
import asyncio
import logging
from typing import Dict, Any
from .base import Analyzer

logger = logging.getLogger(__name__)

class OutdatedAnalyzer(Analyzer):
    name = "outdated_packages"
    base_url = "https://api.deps.dev/v3/systems"

    async def analyze(self, sbom: Dict[str, Any], settings: Dict[str, Any] = None) -> Dict[str, Any]:
        components = sbom.get("components", [])
        results = []
        
        async with httpx.AsyncClient() as client:
            tasks = []
            for component in components:
                tasks.append(self._check_component(client, component))
            
            component_results = await asyncio.gather(*tasks)
            results = [r for r in component_results if r]

        return {"outdated_dependencies": results}

    async def _check_component(self, client: httpx.AsyncClient, component: Dict[str, Any]) -> Dict[str, Any]:
        purl = component.get("purl", "")
        name = component.get("name", "")
        version = component.get("version", "")
        
        system = None
        if purl.startswith("pkg:pypi/"):
            system = "pypi"
        elif purl.startswith("pkg:npm/"):
            system = "npm"
        elif purl.startswith("pkg:maven/"):
            system = "maven"
        elif purl.startswith("pkg:go/"):
            system = "go"
        
        if not system or not name or not version:
            return None

        # Encode name for URL
        encoded_name = name
        if system == "npm" and "/" in name:
            encoded_name = name.replace("/", "%2F")
        
        # Deps.dev API expects 'pypi' to be lowercase
        
        url = f"{self.base_url}/{system}/packages/{encoded_name}"
        
        try:
            response = await client.get(url, follow_redirects=True)
            if response.status_code == 200:
                data = response.json()
                versions_info = data.get("versions", [])
                
                default_version = None
                # Find the version marked as default (usually the latest stable)
                for v in versions_info:
                    if v.get("isDefault"):
                        default_version = v.get("versionKey", {}).get("version")
                        break
                
                # If a default version is found and differs from the current one
                if default_version and default_version != version:
                    return {
                        "component": name,
                        "current_version": version,
                        "latest_version": default_version,
                        "purl": purl,
                        "severity": "INFO",
                        "message": f"Update available: {default_version}"
                    }
            return None
        except Exception as e:
            logger.error(f"Error checking outdated for {name}: {e}")
            return None
