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
    """Normalized dependency representation with all available SBOM fields."""
    # Core Identity
    name: str
    version: str
    purl: Optional[str] = None
    type: str = "unknown"
    
    # Licensing
    license: str = ""
    license_url: Optional[str] = None
    
    # Scope and relationships
    scope: Optional[str] = None
    direct: bool = False
    parent_components: List[str] = field(default_factory=list)
    
    # Source/Origin information
    source_type: Optional[str] = None
    source_target: Optional[str] = None
    layer_digest: Optional[str] = None
    found_by: Optional[str] = None
    locations: List[str] = field(default_factory=list)
    
    # Security identifiers
    cpes: List[str] = field(default_factory=list)
    
    # Package metadata
    description: Optional[str] = None
    author: Optional[str] = None
    publisher: Optional[str] = None
    group: Optional[str] = None
    
    # External references
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    download_url: Optional[str] = None
    
    # Checksums
    hashes: Dict[str, str] = field(default_factory=dict)
    
    # Additional properties from SBOM
    properties: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "type": self.type,
            "license": self.license,
            "license_url": self.license_url,
            "scope": self.scope,
            "direct": self.direct,
            "parent_components": self.parent_components,
            "source_type": self.source_type,
            "source_target": self.source_target,
            "layer_digest": self.layer_digest,
            "found_by": self.found_by,
            "locations": self.locations,
            "cpes": self.cpes,
            "description": self.description,
            "author": self.author,
            "publisher": self.publisher,
            "group": self.group,
            "homepage": self.homepage,
            "repository_url": self.repository_url,
            "download_url": self.download_url,
            "hashes": self.hashes,
            "properties": self.properties,
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
        """Parse a single CycloneDX component with all available fields."""
        
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
        license_str, license_url = self._extract_cyclonedx_licenses_full(licenses)
        
        # Extract properties
        layer_digest = None
        found_by = None
        locations = []
        properties = {}
        
        for prop in comp.get("properties", []):
            prop_name = prop.get("name", "")
            prop_value = prop.get("value", "")
            
            # Store all properties
            if prop_name and prop_value:
                properties[prop_name] = prop_value
            
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
        
        # Extract hashes
        hashes = {}
        for h in comp.get("hashes", []):
            alg = h.get("alg", "").lower()
            content = h.get("content", "")
            if alg and content:
                hashes[alg] = content
        
        # Extract external references
        homepage = None
        repository_url = None
        download_url = None
        
        for ref in comp.get("externalReferences", []):
            ref_type = ref.get("type", "").lower()
            ref_url = ref.get("url", "")
            
            if ref_type == "website" and not homepage:
                homepage = ref_url
            elif ref_type in ["vcs", "git"] and not repository_url:
                repository_url = ref_url
            elif ref_type in ["distribution", "download"] and not download_url:
                download_url = ref_url
        
        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=comp.get("type", "library"),
            license=license_str,
            license_url=license_url,
            scope=comp.get("scope"),
            direct=False,  # CycloneDX doesn't always have this
            source_type=source_type,
            source_target=source_target,
            layer_digest=layer_digest,
            found_by=found_by,
            locations=locations,
            cpes=cpes,
            description=comp.get("description"),
            author=comp.get("author"),
            publisher=comp.get("publisher"),
            group=comp.get("group"),
            homepage=homepage,
            repository_url=repository_url,
            download_url=download_url,
            hashes=hashes,
            properties=properties,
        )
    
    def _extract_cyclonedx_licenses_full(self, licenses: List[Any]) -> Tuple[str, Optional[str]]:
        """Extract license string and URL from CycloneDX license array."""
        if not licenses:
            return "", None
        
        license_names = []
        license_url = None
        
        for lic in licenses:
            if isinstance(lic, dict):
                # Could be license object or expression
                if "license" in lic:
                    inner = lic["license"]
                    if isinstance(inner, dict):
                        license_names.append(inner.get("id") or inner.get("name", ""))
                        if not license_url:
                            license_url = inner.get("url")
                elif "expression" in lic:
                    license_names.append(lic["expression"])
                elif "id" in lic:
                    license_names.append(lic["id"])
                    if not license_url:
                        license_url = lic.get("url")
                elif "name" in lic:
                    license_names.append(lic["name"])
                    if not license_url:
                        license_url = lic.get("url")
            elif isinstance(lic, str):
                license_names.append(lic)
        
        return ", ".join(filter(None, license_names)), license_url

    def _extract_cyclonedx_licenses(self, licenses: List[Any]) -> str:
        """Extract license string from CycloneDX license array."""
        license_str, _ = self._extract_cyclonedx_licenses_full(licenses)
        return license_str
    
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
        """Parse a single Syft artifact with all available fields."""
        
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
        license_str, license_url = self._extract_syft_licenses_full(licenses)
        
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
        
        # Extract metadata for additional fields
        metadata = artifact.get("metadata", {})
        
        # Try to determine if direct dependency
        direct = False
        if metadata:
            # Some package types have direct indicators
            if metadata.get("directDependency") or metadata.get("direct"):
                direct = True
        
        # Extract description from metadata
        description = metadata.get("description") or metadata.get("summary")
        
        # Extract author/maintainer info
        author = None
        if metadata.get("authors"):
            if isinstance(metadata["authors"], list):
                author = ", ".join(metadata["authors"])
            else:
                author = str(metadata["authors"])
        elif metadata.get("author"):
            author = metadata["author"]
        elif metadata.get("maintainer"):
            author = metadata["maintainer"]
        
        # Extract homepage and repository from metadata
        homepage = metadata.get("homepage") or metadata.get("url")
        repository_url = metadata.get("source") or metadata.get("repository")
        
        # Extract hashes from metadata if available
        hashes = {}
        for hash_type in ["md5", "sha1", "sha256", "sha512"]:
            if metadata.get(hash_type):
                hashes[hash_type] = metadata[hash_type]
        # Also check for digests array
        for digest in metadata.get("digests", []):
            alg = digest.get("algorithm", "").lower()
            value = digest.get("value", "")
            if alg and value:
                hashes[alg] = value
        
        # Store relevant metadata as properties
        properties = {}
        for key in ["language", "origin", "architecture", "filesAnalyzed"]:
            if metadata.get(key):
                properties[key] = str(metadata[key])
        
        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=pkg_type,
            license=license_str,
            license_url=license_url,
            scope=None,
            direct=direct,
            source_type=source_type,
            source_target=source_target,
            layer_digest=layer_digest,
            found_by=found_by,
            locations=locations,
            cpes=cpes,
            description=description,
            author=author,
            publisher=None,  # Syft doesn't typically have publisher
            group=None,  # Could parse from purl if needed
            homepage=homepage,
            repository_url=repository_url,
            download_url=None,  # Not typically in Syft
            hashes=hashes,
            properties=properties,
        )
    
    def _extract_syft_licenses_full(self, licenses: List[Any]) -> Tuple[str, Optional[str]]:
        """Extract license string and URL from Syft license array."""
        if not licenses:
            return "", None
        
        license_names = []
        license_url = None
        
        for lic in licenses:
            if isinstance(lic, dict):
                # Syft license object
                value = lic.get("value") or lic.get("spdxExpression") or lic.get("type", "")
                if value:
                    license_names.append(value)
                # Check for license URL
                if not license_url:
                    for url_key in ["url", "urls"]:
                        url_val = lic.get(url_key)
                        if url_val:
                            if isinstance(url_val, list) and url_val:
                                license_url = url_val[0]
                            else:
                                license_url = url_val
                            break
            elif isinstance(lic, str):
                license_names.append(lic)
        
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for l in license_names:
            if l not in seen:
                seen.add(l)
                unique.append(l)
        
        return ", ".join(unique), license_url

    def _extract_syft_licenses(self, licenses: List[Any]) -> str:
        """Extract license string from Syft license array."""
        license_str, _ = self._extract_syft_licenses_full(licenses)
        return license_str
    
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
        """Parse a single SPDX package with all available fields."""
        
        name = pkg.get("name")
        version = pkg.get("versionInfo", "unknown")
        
        if not name:
            return None
        
        # SPDX external refs can contain PURL and CPE
        purl = None
        cpes = []
        
        for ref in pkg.get("externalRefs", []):
            ref_type = ref.get("referenceType", "")
            locator = ref.get("referenceLocator", "")
            
            if ref_type == "purl" and not purl:
                purl = locator
            elif ref_type == "cpe22Type" or ref_type == "cpe23Type":
                if locator:
                    cpes.append(locator)
        
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
            elif purl.startswith("pkg:deb/"):
                pkg_type = "deb"
            elif purl.startswith("pkg:rpm/"):
                pkg_type = "rpm"
            elif purl.startswith("pkg:apk/"):
                pkg_type = "apk"
            elif purl.startswith("pkg:cargo/"):
                pkg_type = "cargo"
            elif purl.startswith("pkg:nuget/"):
                pkg_type = "nuget"
            elif purl.startswith("pkg:gem/"):
                pkg_type = "gem"
        
        # Extract checksums/hashes
        hashes = {}
        for checksum in pkg.get("checksums", []):
            alg = checksum.get("algorithm", "").lower()
            value = checksum.get("checksumValue", "")
            if alg and value:
                hashes[alg] = value
        
        # Extract homepage from homepage field or external refs
        homepage = pkg.get("homepage")
        if homepage == "NOASSERTION":
            homepage = None
        
        download_url = pkg.get("downloadLocation")
        if download_url == "NOASSERTION" or download_url == "NONE":
            download_url = None
        
        # Extract originator (author/publisher)
        author = None
        publisher = None
        
        originator = pkg.get("originator")
        if originator and originator != "NOASSERTION":
            if originator.startswith("Organization:"):
                publisher = originator.replace("Organization:", "").strip()
            elif originator.startswith("Person:"):
                author = originator.replace("Person:", "").strip()
            else:
                author = originator
        
        supplier = pkg.get("supplier")
        if supplier and supplier != "NOASSERTION" and not publisher:
            if supplier.startswith("Organization:"):
                publisher = supplier.replace("Organization:", "").strip()
        
        # Store additional SPDX-specific info as properties
        properties = {}
        
        if pkg.get("filesAnalyzed") is not None:
            properties["filesAnalyzed"] = str(pkg["filesAnalyzed"])
        
        if pkg.get("packageFileName"):
            properties["packageFileName"] = pkg["packageFileName"]
        
        if pkg.get("sourceInfo"):
            properties["sourceInfo"] = pkg["sourceInfo"]
        
        copyright_text = pkg.get("copyrightText")
        if copyright_text and copyright_text != "NOASSERTION":
            properties["copyright"] = copyright_text
        
        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=pkg_type,
            license=license_str,
            license_url=None,  # SPDX doesn't typically have direct license URLs
            scope=None,
            direct=False,
            source_type=None,  # Would need to be determined from document relationships
            source_target=None,
            layer_digest=None,
            found_by=None,
            locations=[],
            cpes=cpes,
            description=pkg.get("description") or pkg.get("summary"),
            author=author,
            publisher=publisher,
            group=None,
            homepage=homepage,
            repository_url=None,  # Not directly in SPDX package
            download_url=download_url,
            hashes=hashes,
            properties=properties,
        )


# Singleton instance for easy import
sbom_parser = SBOMParser()


def parse_sbom(sbom: Dict[str, Any]) -> ParsedSBOM:
    """Convenience function to parse an SBOM."""
    return sbom_parser.parse(sbom)
