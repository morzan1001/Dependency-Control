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
                # Extract licenses from Syft format
                syft_licenses = artifact.get("licenses", [])
                normalized_licenses = []
                
                if isinstance(syft_licenses, list):
                    for lic in syft_licenses:
                        if isinstance(lic, dict):
                            # Syft stores license objects with value/spdxExpression
                            license_id = lic.get("spdxExpression") or lic.get("value") or lic.get("type", "")
                            if license_id:
                                normalized_licenses.append({"license": {"id": license_id}})
                        elif isinstance(lic, str):
                            normalized_licenses.append({"license": {"id": lic}})
                
                # Extract locations for later use
                locations = []
                layer_id = None
                for loc in artifact.get("locations", []):
                    path = loc.get("path") or loc.get("accessPath", "")
                    if path:
                        locations.append(path)
                    if loc.get("layerID") and not layer_id:
                        layer_id = loc.get("layerID")
                
                # Map Syft artifact to CycloneDX-like structure
                comp = {
                    "name": artifact.get("name"),
                    "version": artifact.get("version"),
                    "purl": artifact.get("purl"),
                    "type": artifact.get("type"),
                    "licenses": normalized_licenses,
                    # Additional metadata for analyzers that need it
                    "_foundBy": artifact.get("foundBy"),
                    "_locations": locations,
                    "_layerID": layer_id,
                    "_cpes": [c.get("cpe") for c in artifact.get("cpes", []) if c.get("cpe")],
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
                
                # Extract license
                license_id = pkg.get("licenseConcluded", "")
                if license_id == "NOASSERTION":
                    license_id = pkg.get("licenseDeclared", "")
                if license_id == "NOASSERTION":
                    license_id = ""
                
                comp = {
                    "name": pkg.get("name"),
                    "version": pkg.get("versionInfo"),
                    "purl": purl,
                    "type": "library", # Default
                    "licenses": [{"license": {"id": license_id}}] if license_id else [],
                    "description": pkg.get("description"),
                }
                components.append(comp)
            return components
            
        return []
    
    def _get_source_info(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts source information from SBOM (image name, directory path, etc.)
        Returns dict with 'type' and 'target' keys.
        """
        result = {"type": None, "target": None}
        
        # CycloneDX metadata
        metadata = sbom.get("metadata", {})
        component = metadata.get("component", {})
        
        if component:
            comp_type = component.get("type", "")
            if comp_type == "container":
                result["type"] = "image"
                name = component.get("name", "")
                version = component.get("version", "")
                result["target"] = f"{name}:{version}" if version else name
            elif comp_type in ["application", "library"]:
                result["type"] = "application"
                result["target"] = component.get("name", "")
        
        # Check CycloneDX properties
        for prop in metadata.get("properties", []):
            name = prop.get("name", "")
            value = prop.get("value", "")
            if name == "syft:source:type":
                result["type"] = value
            elif name == "syft:source:target":
                result["target"] = value
            elif name == "aquasecurity:trivy:ImageName":
                result["type"] = "image"
                result["target"] = value
        
        # Syft JSON format
        source = sbom.get("source", {})
        if source:
            source_type = source.get("type", "")
            result["type"] = source_type
            result["target"] = (
                source.get("target", "") or
                source.get("metadata", {}).get("userInput", "") or
                source.get("metadata", {}).get("imageID", "")
            )
        
        return result
