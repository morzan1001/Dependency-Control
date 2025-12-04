import httpx
import asyncio
from typing import Dict, Any, List
from .base import Analyzer

class OSVAnalyzer(Analyzer):
    name = "osv"
    api_url = "https://api.osv.dev/v1/query"

    async def analyze(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        components = sbom.get("components", [])
        results = []
        
        async with httpx.AsyncClient() as client:
            tasks = []
            # OSV supports batch queries, but let's do concurrent single queries for simplicity 
            # or check if batch is better. Batch is definitely better for rate limits.
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
                    print(f"OSV Batch API error: {response.status_code}")
                    
            except Exception as e:
                print(f"OSV Analysis Exception: {e}")

        return {"osv_vulnerabilities": results}
