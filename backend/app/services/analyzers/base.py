from abc import ABC, abstractmethod
from typing import Dict, Any, List

class Analyzer(ABC):
    name: str

    @abstractmethod
    async def analyze(self, sbom: Dict[str, Any], settings: Dict[str, Any] = None) -> Dict[str, Any]:
        pass

    def _get_components(self, sbom: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Normalizes component extraction from different SBOM formats (CycloneDX, Syft, SPDX).
        Returns a list of components with at least 'name', 'version', 'purl', 'type'.
        """
        components = []
        
        # 1. CycloneDX (standard 'components' list)
        if "components" in sbom:
            return sbom["components"]
            
        # 2. Syft JSON (uses 'artifacts')
        if "artifacts" in sbom:
            for artifact in sbom["artifacts"]:
                # Map Syft artifact to CycloneDX-like structure
                comp = {
                    "name": artifact.get("name"),
                    "version": artifact.get("version"),
                    "purl": artifact.get("purl"),
                    "type": artifact.get("type"),
                    "licenses": [{"license": {"id": l}} for l in artifact.get("licenses", [])] if isinstance(artifact.get("licenses"), list) else []
                }
                components.append(comp)
            return components

        # 3. SPDX (uses 'packages')
        if "packages" in sbom:
            for pkg in sbom["packages"]:
                # Map SPDX package to CycloneDX-like structure
                # SPDX externalRefs often contain PURL
                purl = None
                if "externalRefs" in pkg:
                    for ref in pkg["externalRefs"]:
                        if ref.get("referenceType") == "purl":
                            purl = ref.get("referenceLocator")
                            break
                
                comp = {
                    "name": pkg.get("name"),
                    "version": pkg.get("versionInfo"),
                    "purl": purl,
                    "type": "library", # Default
                    "licenses": [{"license": {"id": pkg.get("licenseConcluded")}} ] if pkg.get("licenseConcluded") else []
                }
                components.append(comp)
            return components
            
        return []
