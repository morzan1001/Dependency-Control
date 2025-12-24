import asyncio
import logging
from typing import Any, Dict, List

import httpx

from .base import Analyzer
from .purl_utils import get_registry_system

logger = logging.getLogger(__name__)


class OutdatedAnalyzer(Analyzer):
    name = "outdated_packages"
    base_url = "https://api.deps.dev/v3/systems"

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Dict[str, Any] = None,
        parsed_components: List[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        results = []

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Process in batches to avoid overwhelming deps.dev API
            batch_size = 25
            for i in range(0, len(components), batch_size):
                batch = components[i:i + batch_size]
                tasks = [self._check_component(client, comp) for comp in batch]
                
                component_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in component_results:
                    if result and not isinstance(result, Exception):
                        results.append(result)
                
                # Small delay between batches to avoid rate limits
                if i + batch_size < len(components):
                    await asyncio.sleep(0.1)

        return {"outdated_dependencies": results}

    async def _check_component(
        self, client: httpx.AsyncClient, component: Dict[str, Any]
    ) -> Dict[str, Any]:
        purl = component.get("purl", "")
        name = component.get("name", "")
        version = component.get("version", "")

        # Use centralized PURL parsing
        system = get_registry_system(purl)

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
                        "message": f"Update available: {default_version}",
                    }
            return None
        except httpx.TimeoutException:
            logger.debug(f"Timeout checking outdated for {name}")
            return None
        except httpx.ConnectError:
            logger.debug(f"Connection error checking outdated for {name}")
            return None
        except Exception as e:
            logger.debug(f"Error checking outdated for {name}: {type(e).__name__}")
            return None
