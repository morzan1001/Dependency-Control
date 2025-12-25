import asyncio
import logging
from typing import Any, Dict, List

import httpx

from app.core.cache import cache_service, CacheKeys, CacheTTL
from .base import Analyzer

logger = logging.getLogger(__name__)


class OSVAnalyzer(Analyzer):
    """
    Analyzer that checks packages for known vulnerabilities via the OSV API.
    
    Uses Redis cache to reduce API calls across all pods.
    """
    
    name = "osv"
    api_url = "https://api.osv.dev/v1/query"

    async def analyze(
        self,
        sbom: Dict[str, Any],
        settings: Dict[str, Any] = None,
        parsed_components: List[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        components = self._get_components(sbom, parsed_components)
        results = []

        # Check cache first for all components
        cached_results, uncached_components = await self._get_cached_components(components)
        results.extend(cached_results)
        
        logger.debug(f"OSV: {len(cached_results)} from cache, {len(uncached_components)} to fetch")

        if not uncached_components:
            return {"osv_vulnerabilities": results}

        async with httpx.AsyncClient(timeout=60.0) as client:
            # OSV Batch API: POST https://api.osv.dev/v1/querybatch
            # Process in chunks to avoid payload limits (max ~1000 queries per batch)
            batch_size = 500
            
            for chunk_start in range(0, len(uncached_components), batch_size):
                chunk = uncached_components[chunk_start:chunk_start + batch_size]
                
                batch_payload = {"queries": []}
                valid_components = []

                for component in chunk:
                    purl = component.get("purl")
                    if purl:
                        batch_payload["queries"].append({"package": {"purl": purl}})
                        valid_components.append(component)

                if not batch_payload["queries"]:
                    continue

                try:
                    response = await client.post(
                        "https://api.osv.dev/v1/querybatch", json=batch_payload
                    )
                    if response.status_code == 200:
                        data = response.json()
                        batch_results = data.get("results", [])

                        # Cache results and add to output
                        cache_mapping = {}
                        for comp, res in zip(valid_components, batch_results):
                            vulns = res.get("vulns", [])
                            purl = comp.get("purl", "")
                            
                            # Cache even empty results (with shorter TTL)
                            cache_key = CacheKeys.osv(purl)
                            cache_data = {
                                "component": comp.get("name"),
                                "version": comp.get("version"),
                                "purl": purl,
                                "vulnerabilities": vulns,
                            }
                            cache_mapping[cache_key] = cache_data
                            
                            if vulns:
                                results.append(cache_data)
                        
                        # Batch cache all results
                        if cache_mapping:
                            await cache_service.mset(cache_mapping, CacheTTL.OSV_VULNERABILITY)
                            
                    elif response.status_code == 429:
                        logger.warning("OSV API rate limit hit, waiting...")
                        await asyncio.sleep(5)
                    else:
                        logger.warning(f"OSV Batch API error: {response.status_code}")

                except httpx.TimeoutException:
                    logger.warning(f"OSV API timeout for batch starting at {chunk_start}")
                except httpx.ConnectError:
                    logger.warning("OSV API connection error")
                except Exception as e:
                    logger.warning(f"OSV Analysis Exception: {type(e).__name__}: {e}")
                
                # Small delay between batches
                if chunk_start + batch_size < len(uncached_components):
                    await asyncio.sleep(0.2)

        return {"osv_vulnerabilities": results}

    async def _get_cached_components(
        self, components: List[Dict[str, Any]]
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Check cache for components, return cached results and uncached components."""
        cached_results = []
        uncached_components = []
        
        # Build cache keys for components with PURLs
        cache_keys = []
        component_map = {}
        
        for component in components:
            purl = component.get("purl")
            if purl:
                cache_key = CacheKeys.osv(purl)
                cache_keys.append(cache_key)
                component_map[cache_key] = component
        
        if not cache_keys:
            return [], components
        
        # Batch get from Redis
        cached_data = await cache_service.mget(cache_keys)
        
        for cache_key, data in cached_data.items():
            component = component_map.get(cache_key)
            if not component:
                continue
                
            if data:
                # Only add to results if there are vulnerabilities
                if data.get("vulnerabilities"):
                    cached_results.append(data)
            else:
                uncached_components.append(component)
        
        return cached_results, uncached_components
