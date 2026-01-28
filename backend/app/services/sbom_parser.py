"""
SBOM Parser Module

Provides unified parsing for multiple SBOM formats:
- CycloneDX (1.4, 1.5, 1.6)
- SPDX (2.2, 2.3)
- Syft JSON (native format)

Normalizes all formats to a common internal representation.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.core.constants import (
    APP_PACKAGE_TYPES,
    LICENSE_URL_PATTERNS,
    OS_PACKAGE_TYPES,
    SOURCE_TYPE_APPLICATION,
    SOURCE_TYPE_DIRECTORY,
    SOURCE_TYPE_FILE,
    SOURCE_TYPE_FILE_SYSTEM,
    SOURCE_TYPE_IMAGE,
)
from app.schemas.sbom import ParsedDependency, ParsedSBOM, SBOMFormat

logger = logging.getLogger(__name__)


def is_url(value: str) -> bool:
    """Check if a string is a URL."""
    if not value:
        return False
    try:
        result = urlparse(value)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
        return False


def extract_license_from_url(url: str) -> Optional[str]:
    """Try to extract a license SPDX ID from a license URL."""
    if not url:
        return None

    url_lower = url.lower()

    for pattern, spdx_id in LICENSE_URL_PATTERNS.items():
        if re.search(pattern, url_lower):
            return spdx_id

    return None


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
        if sbom.get("source", {}).get("type") in [
            SOURCE_TYPE_IMAGE,
            SOURCE_TYPE_DIRECTORY,
            SOURCE_TYPE_FILE,
        ]:
            return SBOMFormat.SYFT, None

        return SBOMFormat.UNKNOWN, None

    def parse(self, sbom: Dict[str, Any]) -> ParsedSBOM:
        """Parse an SBOM and return normalized representation."""

        format_type, version = self.detect_format(sbom)

        result = ParsedSBOM(format=format_type, format_version=version)

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
                    result.tool_name = first_tool.get("name") or first_tool.get(
                        "vendor"
                    )
                    result.tool_version = first_tool.get("version")
            elif isinstance(tools, dict):
                # CycloneDX 1.5+ tools object
                components = tools.get("components", [])
                if components:
                    result.tool_name = components[0].get("name")
                    result.tool_version = components[0].get("version")

        result.created_at = metadata.get("timestamp")

        # Source/Subject info (global SBOM source)
        global_source_type, source_target = self._extract_cyclonedx_source(metadata)
        result.source_type = global_source_type
        result.source_target = source_target

        # Get the main component bom-ref (root of dependency tree)
        main_component = metadata.get("component", {})
        main_bom_ref = main_component.get("bom-ref")

        # Parse the dependencies array to build dependency graph
        # CycloneDX dependencies: [{ref: "pkg:...", dependsOn: ["pkg:...", ...]}, ...]
        dependencies_map = sbom.get("dependencies", [])
        direct_refs: set = set()  # Components that are direct dependencies
        all_transitive_refs: set = set()  # All refs that appear in any dependsOn array

        # Build a map of ref -> dependsOn for easier lookup
        deps_graph: Dict[str, list] = {}
        # Build reverse map: child -> list of parents (for parent_components)
        reverse_deps_graph: Dict[str, list] = {}

        for dep_entry in dependencies_map:
            ref = dep_entry.get("ref", "")
            depends_on = dep_entry.get("dependsOn", [])
            deps_graph[ref] = depends_on
            # All items in dependsOn are transitive (dependencies of something)
            for transitive_ref in depends_on:
                all_transitive_refs.add(transitive_ref)
                # Build reverse mapping: child -> parents
                if transitive_ref not in reverse_deps_graph:
                    reverse_deps_graph[transitive_ref] = []
                reverse_deps_graph[transitive_ref].append(ref)

        # Direct dependencies are those that:
        # 1. Appear in the main component's dependsOn list, OR
        # 2. Have their own entry in dependencies but are NOT in any other component's dependsOn
        if main_bom_ref and main_bom_ref in deps_graph:
            # Use the main component's dependsOn as direct dependencies
            direct_refs = set(deps_graph[main_bom_ref])
        else:
            # Fallback: components that have deps_graph entry but are not transitively required
            for ref in deps_graph.keys():
                if ref not in all_transitive_refs and ref != main_bom_ref:
                    direct_refs.add(ref)

        # Log dependency graph info for debugging
        has_dependency_info = bool(dependencies_map)
        logger.debug(
            f"CycloneDX dependency analysis: has_graph={has_dependency_info}, "
            f"main_bom_ref={main_bom_ref}, "
            f"direct_refs={len(direct_refs)}, transitive_refs={len(all_transitive_refs)}, "
            f"reverse_deps_entries={len(reverse_deps_graph)}"
        )

        # Parse components
        components = sbom.get("components", [])
        for comp in components:
            parsed = self._parse_cyclonedx_component(
                comp,
                global_source_type,
                source_target,
                direct_refs,
                all_transitive_refs,
                reverse_deps_graph,
            )
            if parsed:
                result.dependencies.append(parsed)
            else:
                result.skipped_components += 1

    def _extract_cyclonedx_source(
        self, metadata: Dict[str, Any]
    ) -> Tuple[Optional[str], Optional[str]]:
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
                source_type = SOURCE_TYPE_IMAGE
                source_target = (
                    f"{comp_name}:{comp_version}" if comp_version else comp_name
                )
            elif comp_type in ["application", "library"]:
                source_type = SOURCE_TYPE_APPLICATION
                source_target = comp_name
            elif comp_type == "file":
                source_type = SOURCE_TYPE_FILE
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
                source_type = SOURCE_TYPE_IMAGE
                source_target = value
            elif "image" in name.lower() and not source_type:
                source_type = SOURCE_TYPE_IMAGE

        return source_type, source_target

    def _determine_component_source(
        self,
        purl: str,
        pkg_type: str,
        layer_digest: Optional[str],
        locations: List[str],
        global_source_type: Optional[str],
    ) -> Optional[str]:
        """
        Determine the most likely source of a component.

        Returns:
            - "image": OS package from container base image
            - "application": Application dependency from source code
            - "file": From a specific file
            - None: Unknown
        """
        # Normalize package type from PURL
        purl_type = None
        if purl:
            # Extract type from purl: pkg:TYPE/...
            if purl.startswith("pkg:"):
                purl_parts = purl[4:].split("/", 1)
                if purl_parts:
                    purl_type = purl_parts[0].lower()

        effective_type = (purl_type or pkg_type or "").lower()

        # OS packages with layer info are definitely from the container image
        if effective_type in OS_PACKAGE_TYPES:
            if layer_digest:
                return SOURCE_TYPE_IMAGE
            # OS packages without layer info - still likely from image
            if global_source_type == SOURCE_TYPE_IMAGE:
                return SOURCE_TYPE_IMAGE

        # Application packages are typically from source code, not the base image
        if effective_type in APP_PACKAGE_TYPES:
            # Check if there's a location that looks like app code
            for loc in locations:
                loc_lower = loc.lower()
                # Common app dependency locations
                if any(
                    pattern in loc_lower
                    for pattern in [
                        "node_modules",
                        "site-packages",
                        ".venv",
                        "vendor",
                        "requirements",
                        "package.json",
                        "go.mod",
                        "cargo.toml",
                        "pom.xml",
                        "build.gradle",
                        "gemfile",
                        ".csproj",
                    ]
                ):
                    return SOURCE_TYPE_APPLICATION

            # Even without location hints, app packages are usually from the app
            return SOURCE_TYPE_APPLICATION

        # If we have layer info, it's from the image
        if layer_digest:
            return SOURCE_TYPE_IMAGE

        # Fallback to global source type
        return global_source_type

    def _parse_cyclonedx_component(
        self,
        comp: Dict[str, Any],
        global_source_type: Optional[str],
        source_target: Optional[str],
        direct_refs: Optional[set] = None,
        all_transitive_refs: Optional[set] = None,
        reverse_deps_graph: Optional[dict] = None,
    ) -> Optional[ParsedDependency]:
        """Parse a single CycloneDX component with all available fields."""

        purl = comp.get("purl")
        name = comp.get("name")
        version = comp.get("version", "unknown")
        bom_ref = comp.get("bom-ref")

        # Skip components without identifiable info
        if not purl and not name:
            return None

        # If no purl, try to construct one or skip
        if not purl:
            # For now, skip components without PURL
            # Could be enhanced to construct PURL from type+name+version
            return None

        # Determine if this is a direct dependency
        direct = False
        parent_components = []
        check_ref = bom_ref or purl

        # Only determine direct status if we have dependency relationship info
        has_dependency_graph = bool(direct_refs) or bool(all_transitive_refs)

        if (
            has_dependency_graph
            and direct_refs is not None
            and all_transitive_refs is not None
        ):
            # Use bom-ref or purl to check
            if check_ref in direct_refs:
                direct = True
            elif check_ref not in all_transitive_refs and direct_refs:
                # Not in anyone's dependsOn and we have explicit direct refs
                # This component might be isolated or a root-level dependency
                direct = True
        # If no dependency graph at all, leave direct as False (unknown)

        # Get parent components from reverse dependency graph
        if reverse_deps_graph and check_ref in reverse_deps_graph:
            parent_components = reverse_deps_graph[check_ref]

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

        # Determine the component-specific source type
        component_type = comp.get("type", "library")
        determined_source_type = self._determine_component_source(
            purl=purl,
            pkg_type=component_type,
            layer_digest=layer_digest,
            locations=locations,
            global_source_type=global_source_type,
        )

        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=component_type,
            license=license_str,
            license_url=license_url,
            scope=comp.get("scope"),
            direct=direct,
            parent_components=parent_components,
            source_type=determined_source_type,
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

    def _extract_cyclonedx_licenses_full(
        self, licenses: List[Any]
    ) -> Tuple[str, Optional[str]]:
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
                        name_or_id = inner.get("id") or inner.get("name", "")
                        url = inner.get("url")

                        # Check if name is actually a URL
                        if is_url(name_or_id):
                            if not license_url:
                                license_url = name_or_id
                            # Try to extract SPDX ID from URL
                            extracted = extract_license_from_url(name_or_id)
                            if extracted:
                                license_names.append(extracted)
                        else:
                            license_names.append(name_or_id)
                            if not license_url and url:
                                license_url = url
                elif "expression" in lic:
                    expr = lic["expression"]
                    if is_url(expr):
                        if not license_url:
                            license_url = expr
                        extracted = extract_license_from_url(expr)
                        if extracted:
                            license_names.append(extracted)
                    else:
                        license_names.append(expr)
                elif "id" in lic:
                    lid = lic["id"]
                    if is_url(lid):
                        if not license_url:
                            license_url = lid
                        extracted = extract_license_from_url(lid)
                        if extracted:
                            license_names.append(extracted)
                    else:
                        license_names.append(lid)
                        if not license_url:
                            license_url = lic.get("url")
                elif "name" in lic:
                    lname = lic["name"]
                    if is_url(lname):
                        if not license_url:
                            license_url = lname
                        extracted = extract_license_from_url(lname)
                        if extracted:
                            license_names.append(extracted)
                    else:
                        license_names.append(lname)
                        if not license_url:
                            license_url = lic.get("url")
            elif isinstance(lic, str):
                # Check if the string is a URL
                if is_url(lic):
                    if not license_url:
                        license_url = lic
                    extracted = extract_license_from_url(lic)
                    if extracted:
                        license_names.append(extracted)
                else:
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
        source_id = source.get("id", "")

        if source_type_raw == SOURCE_TYPE_IMAGE:
            result.source_type = SOURCE_TYPE_IMAGE
            # Get image name from various locations
            result.source_target = (
                source.get("target", "")
                or source.get("metadata", {}).get("userInput", "")
                or source.get("metadata", {}).get("imageID", "")
            )
        elif source_type_raw == SOURCE_TYPE_DIRECTORY:
            result.source_type = SOURCE_TYPE_DIRECTORY
            result.source_target = source.get("target", "")
        elif source_type_raw == SOURCE_TYPE_FILE:
            result.source_type = SOURCE_TYPE_FILE
            result.source_target = source.get("target", "")
        elif source_type_raw == SOURCE_TYPE_FILE_SYSTEM:
            result.source_type = SOURCE_TYPE_FILE_SYSTEM
            result.source_target = source.get("target", "")

        # Get artifacts list for relationship analysis
        artifacts = sbom.get("artifacts", [])

        # Analyze artifactRelationships to determine direct vs transitive
        # Direct dependencies are those directly referenced by the source (root)
        # or by application-level packages (not OS packages)
        relationships = sbom.get("artifactRelationships", [])

        # Find direct artifact IDs - artifacts that the source directly contains/depends on
        direct_artifact_ids = set()
        all_child_ids = set()  # All artifacts that are children of something

        # Build reverse dependency graph: child -> list of parents
        reverse_deps_graph: Dict[str, list] = {}

        for rel in relationships:
            parent = rel.get("parent", "")
            child = rel.get("child", "")
            rel_type = rel.get("type", "")

            # Track all child relationships and build reverse graph
            if child:
                all_child_ids.add(child)
                # Build reverse mapping: child -> parents
                if child not in reverse_deps_graph:
                    reverse_deps_graph[child] = []
                if parent and parent != source_id:  # Don't include source as parent
                    reverse_deps_graph[child].append(parent)

            # Direct dependencies: artifacts directly connected to the source
            if parent == source_id:
                if rel_type in ("contains", "dependency-of", "depends-on"):
                    direct_artifact_ids.add(child)

        # For container images, we need a different heuristic:
        # - Application packages (npm, pip, go, etc.) that are in the top layer are typically direct
        # - OS packages are usually considered as "base image" dependencies (transitive from app perspective)
        # If no explicit relationships from source, use heuristics based on package type

        if not direct_artifact_ids and result.source_type == SOURCE_TYPE_IMAGE:
            # Fallback heuristic for images without clear relationship graph:
            # Consider application-level packages as potentially direct
            for artifact in artifacts:
                artifact_type = artifact.get("type", "")
                # These types are typically application dependencies, not OS packages
                if artifact_type in (
                    "npm",
                    "python",
                    "go-module",
                    "gem",
                    "cargo",
                    "composer",
                    "maven",
                    "gradle",
                    "nuget",
                    "pub",
                ):
                    direct_artifact_ids.add(artifact.get("id"))

        logger.debug(
            f"Syft relationship analysis: {len(direct_artifact_ids)} direct, "
            f"{len(all_child_ids)} total children from {len(relationships)} relationships"
        )

        # Parse artifacts with direct/transitive info
        for artifact in artifacts:
            artifact_id = artifact.get("id", "")
            is_direct = artifact_id in direct_artifact_ids
            parent_components = reverse_deps_graph.get(artifact_id, [])

            parsed = self._parse_syft_artifact(
                artifact,
                result.source_type,
                result.source_target,
                is_direct,
                parent_components,
            )
            if parsed:
                result.dependencies.append(parsed)
            else:
                result.skipped_components += 1

    def _parse_syft_artifact(
        self,
        artifact: Dict[str, Any],
        source_type: Optional[str],
        source_target: Optional[str],
        is_direct: bool = False,
        parent_components: Optional[List[str]] = None,
    ) -> Optional[ParsedDependency]:
        """Parse a single Syft artifact with all available fields."""

        purl = artifact.get("purl")
        name = artifact.get("name")
        version = artifact.get("version", "unknown")

        if parent_components is None:
            parent_components = []

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
            effective_path = (
                access_path if access_path and access_path != path else path
            )

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

        # Use the is_direct parameter passed from relationship analysis
        # Also check metadata for explicit direct indicators as fallback
        direct = is_direct
        if not direct and metadata:
            # Some package types have direct indicators in metadata
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

        # Determine component-specific source type
        determined_source_type = self._determine_component_source(
            purl=purl,
            pkg_type=pkg_type,
            layer_digest=layer_digest,
            locations=locations,
            global_source_type=source_type,
        )

        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=pkg_type,
            license=license_str,
            license_url=license_url,
            scope=None,
            direct=direct,
            parent_components=parent_components,
            source_type=determined_source_type,
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

    def _extract_syft_licenses_full(
        self, licenses: List[Any]
    ) -> Tuple[str, Optional[str]]:
        """Extract license string and URL from Syft license array."""
        if not licenses:
            return "", None

        license_names = []
        license_url = None

        for lic in licenses:
            if isinstance(lic, dict):
                # Syft license object
                value = (
                    lic.get("value") or lic.get("spdxExpression") or lic.get("type", "")
                )
                if value:
                    # Check if value is a URL
                    if is_url(value):
                        if not license_url:
                            license_url = value
                        # Try to extract SPDX ID from URL
                        extracted = extract_license_from_url(value)
                        if extracted:
                            license_names.append(extracted)
                    else:
                        license_names.append(value)

                # Check for license URL in dedicated fields
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
                # Check if string is a URL
                if is_url(lic):
                    if not license_url:
                        license_url = lic
                    extracted = extract_license_from_url(lic)
                    if extracted:
                        license_names.append(extracted)
                else:
                    license_names.append(lic)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for lic in license_names:
            if lic not in seen:
                seen.add(lic)
                unique.append(lic)

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

        # SPDX relationships define dependencies
        # DEPENDS_ON, DEPENDENCY_OF, CONTAINS, etc.
        relationships = sbom.get("relationships", [])

        # Find the document/root package (usually SPDXID = "SPDXRef-DOCUMENT")
        doc_spdx_id = sbom.get("SPDXID", "SPDXRef-DOCUMENT")

        # Build a map of direct dependencies
        # Direct = packages that the root DESCRIBES or CONTAINS
        # Also packages that have DEPENDS_ON from root
        direct_package_ids = set()
        all_dependency_targets = (
            set()
        )  # All packages that are dependencies of something

        # Build reverse dependency graph: child -> list of parents
        reverse_deps_graph: Dict[str, list] = {}

        for rel in relationships:
            rel_type = rel.get("relationshipType", "")
            element_id = rel.get("spdxElementId", "")
            related_id = rel.get("relatedSpdxElement", "")

            # Root package relationships - these are direct deps
            if element_id == doc_spdx_id:
                if rel_type in ["DESCRIBES", "CONTAINS", "DEPENDS_ON"]:
                    direct_package_ids.add(related_id)

            # Track all dependency targets (transitive) and build reverse graph
            if rel_type == "DEPENDS_ON":
                all_dependency_targets.add(related_id)
                # Build reverse mapping: child -> parents
                if related_id not in reverse_deps_graph:
                    reverse_deps_graph[related_id] = []
                reverse_deps_graph[related_id].append(element_id)

        # Also check for packages that depend on others (makes them root-level if not depended upon)
        packages_with_deps = set()
        for rel in relationships:
            if rel.get("relationshipType") == "DEPENDS_ON":
                packages_with_deps.add(rel.get("spdxElementId", ""))

        # SPDX uses "packages" instead of components
        packages = sbom.get("packages", [])

        for pkg in packages:
            pkg_spdx_id = pkg.get("SPDXID", "")

            # Determine if direct
            is_direct = False
            if pkg_spdx_id in direct_package_ids:
                is_direct = True
            elif (
                pkg_spdx_id in packages_with_deps
                and pkg_spdx_id not in all_dependency_targets
            ):
                # Has dependencies but no one depends on it - likely a root package
                is_direct = True

            # Get parent components
            parent_components = reverse_deps_graph.get(pkg_spdx_id, [])

            parsed = self._parse_spdx_package(pkg, is_direct, parent_components)
            if parsed:
                result.dependencies.append(parsed)
            else:
                result.skipped_components += 1

    def _parse_spdx_package(
        self,
        pkg: Dict[str, Any],
        is_direct: bool = False,
        parent_components: Optional[List[str]] = None,
    ) -> Optional[ParsedDependency]:
        """Parse a single SPDX package with all available fields."""

        name = pkg.get("name")
        version = pkg.get("versionInfo", "unknown")

        if not name:
            return None

        if parent_components is None:
            parent_components = []

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
        license_str = (
            license_concluded
            if license_concluded != "NOASSERTION"
            else license_declared
        )
        if license_str == "NOASSERTION":
            license_str = ""

        # Check if license is a URL and try to extract SPDX ID
        license_url = None
        if is_url(license_str):
            license_url = license_str
            extracted = extract_license_from_url(license_str)
            if extracted:
                license_str = extracted
            else:
                license_str = ""  # Clear URL from license field

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

        # Determine source type based on package type
        determined_source_type = self._determine_component_source(
            purl=purl,
            pkg_type=pkg_type,
            layer_digest=None,  # SPDX doesn't have layer info
            locations=[],
            global_source_type=None,
        )

        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=pkg_type,
            license=license_str,
            license_url=license_url,
            scope=None,
            direct=is_direct,
            parent_components=parent_components,
            source_type=determined_source_type,
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
