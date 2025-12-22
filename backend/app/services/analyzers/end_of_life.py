import httpx
import logging
import re
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
from .base import Analyzer

logger = logging.getLogger(__name__)

# Mapping from CPE product names to endoflife.date product IDs
CPE_TO_EOL_MAPPING = {
    "python": "python",
    "node.js": "nodejs",
    "nodejs": "nodejs",
    "go": "go",
    "golang": "go",
    "ruby": "ruby",
    "php": "php",
    "java": "java",
    "openjdk": "java",
    "dotnet": "dotnet",
    ".net": "dotnet",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "mongodb": "mongodb",
    "redis": "redis",
    "elasticsearch": "elasticsearch",
    "nginx": "nginx",
    "apache": "apache",
    "httpd": "apache",
    "kubernetes": "kubernetes",
    "docker": "docker",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "centos": "centos",
    "rhel": "rhel",
    "alpine": "alpine",
    "angular": "angular",
    "react": "react",
    "vue": "vuejs",
    "django": "django",
    "flask": "flask",
    "rails": "rails",
    "spring_framework": "spring-framework",
    "spring_boot": "spring-boot",
    "laravel": "laravel",
    "symfony": "symfony",
    "express": "nodejs",  # Express follows Node.js lifecycle
    "tensorflow": "tensorflow",
    "pytorch": "pytorch",
}


class EndOfLifeAnalyzer(Analyzer):
    name = "end_of_life"
    api_url = "https://endoflife.date/api"

    async def analyze(self, sbom: Dict[str, Any], settings: Dict[str, Any] = None) -> Dict[str, Any]:
        components = self._get_components(sbom)
        results = []
        checked_products: Set[str] = set()  # Avoid duplicate API calls
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            for component in components:
                name = component.get("name", "").lower()
                version = component.get("version", "")
                cpes = component.get("_cpes", [])
                
                # Strategy 1: Try to match via CPE (more accurate)
                eol_products = self._extract_products_from_cpes(cpes)
                
                # Strategy 2: Fallback to component name matching
                if not eol_products:
                    mapped = CPE_TO_EOL_MAPPING.get(name)
                    if mapped:
                        eol_products.add(mapped)
                    else:
                        # Try direct name match
                        eol_products.add(name)
                
                for product in eol_products:
                    if product in checked_products:
                        continue
                    checked_products.add(product)
                    
                    try:
                        response = await client.get(f"{self.api_url}/{product}.json")
                        if response.status_code == 200:
                            cycles = response.json()
                            eol_info = self._check_version(version, cycles)
                            if eol_info:
                                results.append({
                                    "component": component.get("name"),
                                    "version": version,
                                    "product": product,
                                    "eol_info": eol_info
                                })
                    except Exception as e:
                        logger.debug(f"EOL check failed for {product}: {e}")
                        continue
                    
        return {"eol_issues": results}

    def _extract_products_from_cpes(self, cpes: List[str]) -> Set[str]:
        """Extract product names from CPE strings and map to endoflife.date IDs."""
        products = set()
        
        for cpe in cpes:
            # CPE format: cpe:2.3:a:vendor:product:version:...
            # or cpe:/a:vendor:product:version:...
            match = re.match(r'cpe:[:/]2\.3:a:([^:]+):([^:]+)', cpe)
            if not match:
                match = re.match(r'cpe:/a:([^:]+):([^:]+)', cpe)
            
            if match:
                vendor = match.group(1).lower()
                product = match.group(2).lower()
                
                # Try product directly
                if product in CPE_TO_EOL_MAPPING:
                    products.add(CPE_TO_EOL_MAPPING[product])
                # Try vendor:product combo
                elif f"{vendor}_{product}" in CPE_TO_EOL_MAPPING:
                    products.add(CPE_TO_EOL_MAPPING[f"{vendor}_{product}"])
                # Try just product name
                else:
                    products.add(product)
        
        return products

    def _check_version(self, version: str, cycles: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Check if a version matches an EOL cycle."""
        if not version:
            return None
            
        # Clean version string
        clean_version = version.lstrip("v").lower()
        
        for cycle in cycles:
            cycle_version = str(cycle.get("cycle", ""))
            
            # Check various matching strategies
            if self._version_matches_cycle(clean_version, cycle_version):
                eol = cycle.get("eol")
                
                # eol can be: date string, True (already EOL), False (not EOL)
                if eol is True:
                    return cycle
                elif eol and eol is not False:
                    try:
                        eol_date = datetime.strptime(str(eol), "%Y-%m-%d")
                        if eol_date < datetime.now():
                            return cycle
                    except ValueError:
                        pass
        return None

    def _version_matches_cycle(self, version: str, cycle: str) -> bool:
        """Check if a version belongs to a cycle."""
        if not version or not cycle:
            return False
            
        # Direct match
        if version == cycle:
            return True
            
        # Version starts with cycle (e.g., "3.8.5" matches cycle "3.8")
        if version.startswith(f"{cycle}."):
            return True
            
        # Major version match (e.g., "3" matches "3.x")
        if "." in version:
            major = version.split(".")[0]
            if cycle == major:
                return True
            # Check major.minor match
            if version.count(".") >= 1:
                major_minor = ".".join(version.split(".")[:2])
                if cycle == major_minor:
                    return True
        
        return False
