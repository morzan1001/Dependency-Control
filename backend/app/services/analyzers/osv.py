import asyncio
import logging
from typing import Any, Dict, List

import httpx

from .base import Analyzer

logger = logging.getLogger(__name__)


class OSVAnalyzer(Analyzer):
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

        async with httpx.AsyncClient(timeout=60.0) as client:
            # OSV Batch API: POST https://api.osv.dev/v1/querybatch
            # Process in chunks to avoid payload limits (max ~1000 queries per batch)
            batch_size = 500
            
            for chunk_start in range(0, len(components), batch_size):
                chunk = components[chunk_start:chunk_start + batch_size]
                
                batch_payload = {"queries": []}
                valid_indices = []

                for i, component in enumerate(chunk):
                    purl = component.get("purl")
                    if purl:
                        batch_payload["queries"].append({"package": {"purl": purl}})
                        valid_indices.append(chunk_start + i)

                if not batch_payload["queries"]:
                    continue

                try:
                    response = await client.post(
                        "https://api.osv.dev/v1/querybatch", json=batch_payload
                    )
                    if response.status_code == 200:
                        data = response.json()
                        batch_results = data.get("results", [])

                        for idx, res in enumerate(batch_results):
                            vulns = res.get("vulns", [])
                            if vulns:
                                # Map back to component
                                comp_idx = valid_indices[idx]
                                comp = components[comp_idx]
                                results.append(
                                    {
                                        "component": comp.get("name"),
                                        "version": comp.get("version"),
                                        "purl": comp.get("purl"),
                                        "vulnerabilities": vulns,
                                    }
                                )
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
                if chunk_start + batch_size < len(components):
                    await asyncio.sleep(0.2)

        return {"osv_vulnerabilities": results}
