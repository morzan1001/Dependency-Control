import httpx
import logging
from typing import Dict, Any
from .base import Analyzer

logger = logging.getLogger(__name__)

class OSVAnalyzer(Analyzer):
    name = "osv"
    api_url = "https://api.osv.dev/v1/query"

    async def analyze(self, sbom: Dict[str, Any], settings: Dict[str, Any] = None) -> Dict[str, Any]:
        components = self._get_components(sbom)
        results = []
        
        async with httpx.AsyncClient() as client:
            # OSV Batch API: POST https://api.osv.dev/v1/querybatch
            
            batch_payload = {"queries": []}
            valid_indices = []
            
            for i, component in enumerate(components):
                purl = component.get("purl")
                if purl:
                    batch_payload["queries"].append({"package": {"purl": purl}})
                    valid_indices.append(i)
            
            if not batch_payload["queries"]:
                return {"results": []}

            try:
                response = await client.post("https://api.osv.dev/v1/querybatch", json=batch_payload)
                if response.status_code == 200:
                    data = response.json()
                    batch_results = data.get("results", [])
                    
                    for idx, res in enumerate(batch_results):
                        vulns = res.get("vulns", [])
                        if vulns:
                            # Map back to component
                            comp_idx = valid_indices[idx]
                            comp = components[comp_idx]
                            results.append({
                                "component": comp.get("name"),
                                "version": comp.get("version"),
                                "purl": comp.get("purl"),
                                "vulnerabilities": vulns
                            })
                else:
                    logger.error(f"OSV Batch API error: {response.status_code}")
                    
            except Exception as e:
                logger.error(f"OSV Analysis Exception: {e}")

        return {"osv_vulnerabilities": results}
