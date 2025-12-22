"""
SBOM Parser Module

Provides unified parsing for multiple SBOM formats:
- CycloneDX (1.4, 1.5, 1.6)
- SPDX (2.2, 2.3)
- Syft JSON (native format)

Normalizes all formats to a common internal representation.
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging
import re

logger = logging.getLogger(__name__)


class SBOMFormat(Enum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"
    SYFT = "syft"
    UNKNOWN = "unknown"


class SourceType(Enum):
    IMAGE = "image"
    DIRECTORY = "directory"
    FILE = "file"
    APPLICATION = "application"
    FILESYSTEM = "file-system"
    UNKNOWN = "unknown"


@dataclass
class ParsedDependency:
    """Normalized dependency representation."""
    name: str
    version: str
    purl: Optional[str] = None
    type: str = "unknown"
    license: str = ""
    scope: Optional[str] = None
    direct: bool = False
    
    # Source/Origin information
    source_type: Optional[str] = None
    source_target: Optional[str] = None
    layer_digest: Optional[str] = None
    found_by: Optional[str] = None
    locations: List[str] = field(default_factory=list)
    
    # Additional metadata
    cpes: List[str] = field(default_factory=list)
    description: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "type": self.type,
            "license": self.license,
            "scope": self.scope,
            "direct": self.direct,
            "source_type": self.source_type,
            "source_target": self.source_target,
            "layer_digest": self.layer_digest,
            "found_by": self.found_by,
            "locations": self.locations,
            "cpes": self.cpes,
            "description": self.description,
        }


@dataclass
class ParsedSBOM:
    """Normalized SBOM representation."""
    format: SBOMFormat
    format_version: Optional[str] = None
    
    # Source information
    source_type: Optional[str] = None
    source_target: Optional[str] = None
    
    # Components/Dependencies
    dependencies: List[ParsedDependency] = field(default_factory=list)
    
    # Metadata
    tool_name: Optional[str] = None
    tool_version: Optional[str] = None
    created_at: Optional[str] = None
    
    # Statistics
    total_components: int = 0
    parsed_components: int = 0
    skipped_components: int = 0


class SBOMParser:
    """
    Universal SBOM parser that handles multiple formats and normalizes output.
    """
    
    def __init__(self):
        self.format_handlers = {
            SBOMFormat.CYCLONEDX: self._parse_cyclonedx,
            SBOMFormat.SPDX: self._parse_spdx,
            SBOMFormat.SYFT: self._parse_syft,
        }
    
    def detect_format(self, sbom: Dict[str, Any]) -> Tuple[SBOMFormat, Optional[str]]:
        """Detect the SBOM format and version."""
        
        # CycloneDX detection
        if sbom.get("bomFormat") == "CycloneDX":
            return SBOMFormat.CYCLONEDX, sbom.get("specVersion")
        
        # Check for CycloneDX schema
        schema = sbom.get("$schema", "")
        if "cyclonedx" in schema.lower():
            version_match = re.search(r"bom-(\d+\.\d+)", schema)
            version = version_match.group(1) if version_match else None
            return SBOMFormat.CYCLONEDX, version
        
        # CycloneDX by structure (has components array with purl)
        if "components" in sbom and isinstance(sbom.get("components"), list):
            if sbom.get("components") and "purl" in sbom["components"][0]:
                return SBOMFormat.CYCLONEDX, sbom.get("specVersion")
        
        # SPDX detection
        if sbom.get("spdxVersion"):
            return SBOMFormat.SPDX, sbom.get("spdxVersion")
        
        if "SPDX" in sbom.get("$schema", ""):
            return SBOMFormat.SPDX, None
        
        # Syft JSON detection (has artifacts array)
        if "artifacts" in sbom and isinstance(sbom.get("artifacts"), list):
            # Check for Syft descriptor
            descriptor = sbom.get("descriptor", {})
            if descriptor.get("name") == "syft":
                return SBOMFormat.SYFT, descriptor.get("version")
            # Even without descriptor, artifacts + source is Syft-like
            if "source" in sbom:
                return SBOMFormat.SYFT, None
        
        # Fallback: Check for common Syft patterns
        if sbom.get("source", {}).get("type") in ["image", "directory", "file"]:
            return SBOMFormat.SYFT, None
        
        return SBOMFormat.UNKNOWN, None
    
    def parse(self, sbom: Dict[str, Any]) -> ParsedSBOM:
        """Parse an SBOM and return normalized representation."""
        
        format_type, version = self.detect_format(sbom)
        
        result = ParsedSBOM(
            format=format_type,
            format_version=version
        )
        
        if format_type == SBOMFormat.UNKNOWN:
            logger.warning("Unknown SBOM format, attempting best-effort parsing")
            # Try all parsers
            for handler in self.format_handlers.values():
                try:
                    handler(sbom, result)
                    if result.dependencies:
                        break
                except Exception:
                    continue
        else:
            handler = self.format_handlers.get(format_type)
            if handler:
                try:
                    handler(sbom, result)
                except Exception as e:
                    logger.error(f"Error parsing {format_type.value} SBOM: {e}")
        
        result.total_components = len(result.dependencies) + result.skipped_components
        result.parsed_components = len(result.dependencies)
        
        return result
    
    def _parse_cyclonedx(self, sbom: Dict[str, Any], result: ParsedSBOM):
        """Parse CycloneDX format SBOM."""
        
        # Extract metadata
        metadata = sbom.get("metadata", {})
        
        # Tool info
        tools = metadata.get("tools", [])
        if tools:
            if isinstance(tools, list) and len(tools) > 0:
                first_tool = tools[0]
                if isinstance(first_tool, dict):
                    result.tool_name = first_tool.get("name") or first_tool.get("vendor")
                    result.tool_version = first_tool.get("version")
            elif isinstance(tools, dict):
                # CycloneDX 1.5+ tools object
                components = tools.get("components", [])
                if components:
                    result.tool_name = components[0].get("name")
                    result.tool_version = components[0].get("version")
        
        result.created_at = metadata.get("timestamp")
        
        # Source/Subject info
        source_type, source_target = self._extract_cyclonedx_source(metadata)
        result.source_type = source_type
        result.source_target = source_target
        
        # Parse components
        components = sbom.get("components", [])
        for comp in components:
            parsed = self._parse_cyclonedx_component(comp, source_type, source_target)
            if parsed:
                result.dependencies.append(parsed)
            else:
                result.skipped_components += 1
    
    def _extract_cyclonedx_source(self, metadata: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Extract source information from CycloneDX metadata."""
        
        source_type = None
        source_target = None
        
        # Check component (main subject)
        component = metadata.get("component", {})
        if component:
            comp_type = component.get("type", "")
            comp_name = component.get("name", "")
            comp_version = component.get("version", "")
            
            if comp_type == "container":
                source_type = "image"
                source_target = f"{comp_name}:{comp_version}" if comp_version else comp_name
            elif comp_type in ["application", "library"]:
                source_type = "application"
                source_target = comp_name
            elif comp_type == "file":
                source_type = "file"
                source_target = comp_name
        
        # Check properties for syft/trivy hints
        for prop in metadata.get("properties", []):
            name = prop.get("name", "")
            value = prop.get("value", "")
            
            if name == "syft:source:type":
                source_type = value
            elif name == "syft:source:target":
                source_target = value
            elif name == "aquasecurity:trivy:ImageName":
                source_type = "image"
                source_target = value
            elif "image" in name.lower() and not source_type:
                source_type = "image"
        
        return source_type, source_target
    
    def _parse_cyclonedx_component(
        self, 
        comp: Dict[str, Any],
        source_type: Optional[str],
        source_target: Optional[str]
    ) -> Optional[ParsedDependency]:
        """Parse a single CycloneDX component."""
        
        purl = comp.get("purl")
        name = comp.get("name")
        version = comp.get("version", "unknown")
        
        # Skip components without identifiable info
        if not purl and not name:
            return None
        
        # If no purl, try to construct one or skip
        if not purl:
            # For now, skip components without PURL
            # Could be enhanced to construct PURL from type+name+version
            return None
        
        # Extract license
        licenses = comp.get("licenses", [])
        license_str = self._extract_cyclonedx_licenses(licenses)
        
        # Extract properties
        layer_digest = None
        found_by = None
        locations = []
        
        for prop in comp.get("properties", []):
            prop_name = prop.get("name", "")
            prop_value = prop.get("value", "")
            
            # Layer info (Trivy)
            if prop_name in ["trivy:LayerDigest", "aquasecurity:trivy:LayerDigest"]:
                layer_digest = prop_value
            elif prop_name == "aquasecurity:trivy:LayerDiffID":
                if not layer_digest:
                    layer_digest = prop_value
            
            # Cataloger (Syft)
            elif prop_name == "syft:package:foundBy":
                found_by = prop_value
            
            # Locations
            elif "location" in prop_name.lower() or "path" in prop_name.lower():
                if prop_value:
                    locations.append(prop_value)
        
        # Check evidence for locations
        evidence = comp.get("evidence", {})
        for occ in evidence.get("occurrences", []):
            loc = occ.get("location")
            if loc and loc not in locations:
                locations.append(loc)
        
        # Extract CPEs
        cpes = [c.get("cpe") for c in comp.get("cpes", []) if c.get("cpe")]
        
        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=comp.get("type", "library"),
            license=license_str,
            scope=comp.get("scope"),
            direct=False,  # CycloneDX doesn't always have this
            source_type=source_type,
            source_target=source_target,
            layer_digest=layer_digest,
            found_by=found_by,
            locations=locations,
            cpes=cpes,
            description=comp.get("description"),
        )
    
    def _extract_cyclonedx_licenses(self, licenses: List[Any]) -> str:
        """Extract license string from CycloneDX license array."""
        if not licenses:
            return ""
        
        license_names = []
        for lic in licenses:
            if isinstance(lic, dict):
                # Could be license object or expression
                if "license" in lic:
                    inner = lic["license"]
                    if isinstance(inner, dict):
                        license_names.append(inner.get("id") or inner.get("name", ""))
                elif "expression" in lic:
                    license_names.append(lic["expression"])
                elif "id" in lic:
                    license_names.append(lic["id"])
                elif "name" in lic:
                    license_names.append(lic["name"])
            elif isinstance(lic, str):
                license_names.append(lic)
        
        return ", ".join(filter(None, license_names))
    
    def _parse_syft(self, sbom: Dict[str, Any], result: ParsedSBOM):
        """Parse Syft JSON format SBOM."""
        
        # Extract descriptor (tool info)
        descriptor = sbom.get("descriptor", {})
        result.tool_name = descriptor.get("name", "syft")
        result.tool_version = descriptor.get("version")
        
        # Extract source info
        source = sbom.get("source", {})
        source_type_raw = source.get("type", "")
        
        if source_type_raw == "image":
            result.source_type = "image"
            # Get image name from various locations
            result.source_target = (
                source.get("target", "") or
                source.get("metadata", {}).get("userInput", "") or
                source.get("metadata", {}).get("imageID", "")
            )
        elif source_type_raw == "directory":
            result.source_type = "directory"
            result.source_target = source.get("target", "")
        elif source_type_raw == "file":
            result.source_type = "file"
            result.source_target = source.get("target", "")
        elif source_type_raw == "file-system":
            result.source_type = "file-system"
            result.source_target = source.get("target", "")
        
        # Parse artifacts
        artifacts = sbom.get("artifacts", [])
        for artifact in artifacts:
            parsed = self._parse_syft_artifact(artifact, result.source_type, result.source_target)
            if parsed:
                result.dependencies.append(parsed)
            else:
                result.skipped_components += 1
    
    def _parse_syft_artifact(
        self,
        artifact: Dict[str, Any],
        source_type: Optional[str],
        source_target: Optional[str]
    ) -> Optional[ParsedDependency]:
        """Parse a single Syft artifact."""
        
        purl = artifact.get("purl")
        name = artifact.get("name")
        version = artifact.get("version", "unknown")
        
        # Skip artifacts without identifiable info
        if not purl and not name:
            return None
        
        # If no purl, skip (could enhance to construct)
        if not purl:
            return None
        
        # Extract license
        licenses = artifact.get("licenses", [])
        license_str = self._extract_syft_licenses(licenses)
        
        # Extract locations and layer info
        locations = []
        layer_digest = None
        
        for loc in artifact.get("locations", []):
            path = loc.get("path", "")
            layer_id = loc.get("layerID", "")
            access_path = loc.get("accessPath", "")
            
            # Use accessPath if different from path
            effective_path = access_path if access_path and access_path != path else path
            
            if effective_path and effective_path not in locations:
                locations.append(effective_path)
            
            # Get layer digest from first location with layerID
            if layer_id and not layer_digest:
                layer_digest = layer_id
        
        # Extract CPEs
        cpes = [c.get("cpe") for c in artifact.get("cpes", []) if c.get("cpe")]
        
        # Get foundBy (cataloger)
        found_by = artifact.get("foundBy")
        
        # Determine package type from artifact type
        pkg_type = artifact.get("type", "unknown")
        
        # Try to determine if direct dependency
        # Syft doesn't directly provide this, but we can infer from metadata
        direct = False
        metadata = artifact.get("metadata", {})
        if metadata:
            # Some package types have direct indicators
            if metadata.get("directDependency") or metadata.get("direct"):
                direct = True
        
        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=pkg_type,
            license=license_str,
            scope=None,
            direct=direct,
            source_type=source_type,
            source_target=source_target,
            layer_digest=layer_digest,
            found_by=found_by,
            locations=locations,
            cpes=cpes,
            description=None,
        )
    
    def _extract_syft_licenses(self, licenses: List[Any]) -> str:
        """Extract license string from Syft license array."""
        if not licenses:
            return ""
        
        license_names = []
        for lic in licenses:
            if isinstance(lic, dict):
                # Syft license object
                value = lic.get("value") or lic.get("spdxExpression") or lic.get("type", "")
                if value:
                    license_names.append(value)
            elif isinstance(lic, str):
                license_names.append(lic)
        
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for l in license_names:
            if l not in seen:
                seen.add(l)
                unique.append(l)
        
        return ", ".join(unique)
    
    def _parse_spdx(self, sbom: Dict[str, Any], result: ParsedSBOM):
        """Parse SPDX format SBOM."""
        
        result.tool_name = "spdx"
        result.format_version = sbom.get("spdxVersion")
        result.created_at = sbom.get("creationInfo", {}).get("created")
        
        # SPDX uses "packages" instead of components
        packages = sbom.get("packages", [])
        
        for pkg in packages:
            parsed = self._parse_spdx_package(pkg)
            if parsed:
                result.dependencies.append(parsed)
            else:
                result.skipped_components += 1
    
    def _parse_spdx_package(self, pkg: Dict[str, Any]) -> Optional[ParsedDependency]:
        """Parse a single SPDX package."""
        
        name = pkg.get("name")
        version = pkg.get("versionInfo", "unknown")
        
        if not name:
            return None
        
        # SPDX external refs can contain PURL
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        
        # Skip if no PURL (could be enhanced)
        if not purl:
            return None
        
        # Extract license
        license_concluded = pkg.get("licenseConcluded", "")
        license_declared = pkg.get("licenseDeclared", "")
        license_str = license_concluded if license_concluded != "NOASSERTION" else license_declared
        if license_str == "NOASSERTION":
            license_str = ""
        
        # Try to determine type from PURL
        pkg_type = "unknown"
        if purl:
            if purl.startswith("pkg:npm/"):
                pkg_type = "npm"
            elif purl.startswith("pkg:pypi/"):
                pkg_type = "python"
            elif purl.startswith("pkg:maven/"):
                pkg_type = "java"
            elif purl.startswith("pkg:golang/"):
                pkg_type = "go-module"
            # Add more as needed
        
        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=pkg_type,
            license=license_str,
            description=pkg.get("description"),
        )


# Singleton instance for easy import
sbom_parser = SBOMParser()


def parse_sbom(sbom: Dict[str, Any]) -> ParsedSBOM:
    """Convenience function to parse an SBOM."""
    return sbom_parser.parse(sbom)
