import httpx
import asyncio
from typing import Dict, Any
from .base import Analyzer

class DepsDevAnalyzer(Analyzer):
    name = "deps_dev"
    base_url = "https://api.deps.dev/v1/systems"

    async def analyze(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        components = sbom.get("components", [])
        results = []
        
        async with httpx.AsyncClient() as client:
            tasks = []
            for component in components:
                tasks.append(self._check_component(client, component))
            
            component_results = await asyncio.gather(*tasks)
            results = [r for r in component_results if r]

        return {"scorecard_issues": results}

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

        # Encode name for URL (especially for scoped npm packages or maven groups)
        # Maven: group:artifact -> group:artifact (deps.dev expects colon)
        # NPM: @scope/pkg -> @scope%2Fpkg
        encoded_name = name
        if system == "npm" and "/" in name:
            encoded_name = name.replace("/", "%2F")
        
        url = f"{self.base_url}/{system}/packages/{encoded_name}/versions/{version}"
        
        try:
            response = await client.get(url)
            if response.status_code == 200:
                data = response.json()
                # Extract Scorecard data if available
                projects = data.get("relatedProjects", [])
                if projects:
                    # Usually the first one is the source repo
                    project_key = projects[0] 
                    # Now fetch project details for scorecard
                    # https://api.deps.dev/v1/projects/{type}/{name}
                    # But wait, the version endpoint often has 'links' to the repo.
                    # Let's try to get the scorecard directly if possible or infer it.
                    # Actually deps.dev returns scorecard in the project endpoint.
                    
                    proj_type = project_key.get("projectKey", {}).get("id", {}).get("type")
                    proj_id = project_key.get("projectKey", {}).get("id", {}).get("name")
                    
                    if proj_type and proj_id:
                        encoded_proj_id = proj_id.replace("/", "%2F")
                        proj_url = f"https://api.deps.dev/v1/projects/{proj_type}/{encoded_proj_id}"
                        proj_res = await client.get(proj_url)
                        if proj_res.status_code == 200:
                            proj_data = proj_res.json()
                            scorecard = proj_data.get("scorecard")
                            if scorecard:
                                overall = scorecard.get("overallScore", 0)
                                if overall < 5.0: # Threshold for warning
                                    return {
                                        "component": name,
                                        "version": version,
                                        "scorecard": scorecard,
                                        "warning": f"Low OpenSSF Scorecard score: {overall}/10"
                                    }
            return None
        except Exception:
            return None
