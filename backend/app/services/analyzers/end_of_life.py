import httpx
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from .base import Analyzer

logger = logging.getLogger(__name__)

class EndOfLifeAnalyzer(Analyzer):
    name = "end_of_life"
    api_url = "https://endoflife.date/api/v1"

    async def analyze(self, sbom: Dict[str, Any], settings: Dict[str, Any] = None) -> Dict[str, Any]:
        components = self._get_components(sbom)
        results = []
        
        async with httpx.AsyncClient() as client:
            for component in components:
                name = component.get("name", "").lower()
                version = component.get("version", "")
                
                # Basic mapping/check - CPE matching would be more accurate
                try:
                    response = await client.get(f"{self.api_url}/{name}.json")
                    if response.status_code == 200:
                        cycles = response.json()
                        # Check if version matches any cycle
                        eol_info = self._check_version(version, cycles)
                        if eol_info:
                            results.append({
                                "component": name,
                                "version": version,
                                "eol_info": eol_info
                            })
                except Exception as e:
                    logger.error(f"Error checking {name}: {e}")
                    continue
                    
        return {"eol_issues": results}

    def _check_version(self, version: str, cycles: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        # Basic version check - checking if version starts with cycle
        # In production, use semantic versioning comparison
        for cycle in cycles:
            if version.startswith(cycle["cycle"]):
                if cycle.get("eol") and cycle["eol"] is not False:
                     # Check if EOL date is passed
                     try:
                         eol_date = datetime.strptime(cycle["eol"], "%Y-%m-%d")
                         if eol_date < datetime.now():
                             return cycle
                     except ValueError:
                         pass
        return None
