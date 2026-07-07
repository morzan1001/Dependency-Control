"""Unified parsing of CycloneDX, SPDX, and Syft JSON SBOMs into a common representation."""

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
    SPDX_ORGANIZATION_PREFIX,
)
from app.schemas.sbom import ParsedDependency, ParsedSBOM, SBOMFormat
from app.services.analyzers.purl_utils import get_purl_type
from app.services.cbom_parser import parse_crypto_components

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
    """Universal SBOM parser that handles multiple formats and normalizes output."""

    def __init__(self) -> None:
        self.format_handlers = {
            SBOMFormat.CYCLONEDX: self._parse_cyclonedx,
            SBOMFormat.SPDX: self._parse_spdx,
            SBOMFormat.SYFT: self._parse_syft,
        }

    @staticmethod
    def _detect_cyclonedx(sbom: Dict[str, Any]) -> Optional[Tuple[SBOMFormat, Optional[str]]]:
        """Try to detect CycloneDX format."""
        if sbom.get("bomFormat") == "CycloneDX":
            return SBOMFormat.CYCLONEDX, sbom.get("specVersion")

        schema = sbom.get("$schema", "")
        if "cyclonedx" in schema.lower():
            version_match = re.search(r"bom-(\d+\.\d+)", schema)
            version = version_match.group(1) if version_match else None
            return SBOMFormat.CYCLONEDX, version

        # CycloneDX by structure (has components array with purl)
        components = sbom.get("components")
        if isinstance(components, list) and components and isinstance(components[0], dict) and "purl" in components[0]:
            return SBOMFormat.CYCLONEDX, sbom.get("specVersion")

        return None

    @staticmethod
    def _detect_spdx(sbom: Dict[str, Any]) -> Optional[Tuple[SBOMFormat, Optional[str]]]:
        """Try to detect SPDX format."""
        if sbom.get("spdxVersion"):
            return SBOMFormat.SPDX, sbom.get("spdxVersion")

        if "SPDX" in sbom.get("$schema", ""):
            return SBOMFormat.SPDX, None

        return None

    @staticmethod
    def _detect_syft(sbom: Dict[str, Any]) -> Optional[Tuple[SBOMFormat, Optional[str]]]:
        """Try to detect Syft JSON format."""
        if "artifacts" in sbom and isinstance(sbom.get("artifacts"), list):
            descriptor = sbom.get("descriptor", {})
            if descriptor.get("name") == "syft":
                return SBOMFormat.SYFT, descriptor.get("version")
            if "source" in sbom:
                return SBOMFormat.SYFT, None

        # Fallback: Check for common Syft patterns
        source = sbom.get("source")
        if isinstance(source, dict) and source.get("type") in [
            SOURCE_TYPE_IMAGE,
            SOURCE_TYPE_DIRECTORY,
            SOURCE_TYPE_FILE,
        ]:
            return SBOMFormat.SYFT, None

        return None

    def detect_format(self, sbom: Dict[str, Any]) -> Tuple[SBOMFormat, Optional[str]]:
        """Detect the SBOM format and version."""
        result = self._detect_cyclonedx(sbom)
        if result:
            return result

        result = self._detect_spdx(sbom)
        if result:
            return result

        result = self._detect_syft(sbom)
        if result:
            return result

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
            format_handler = self.format_handlers.get(format_type)
            if format_handler is not None:
                try:
                    format_handler(sbom, result)
                except Exception as e:
                    logger.exception("Error parsing %s SBOM: %s", format_type.value, e)

        result.total_components = len(result.dependencies) + result.skipped_components
        result.parsed_components = len(result.dependencies)

        return result

    @staticmethod
    def _extract_cyclonedx_tool(tools: Any) -> Tuple[Optional[str], Optional[str]]:
        """Extract tool name/version from CycloneDX metadata.tools (list or object form)."""
        if not tools:
            return None, None
        if isinstance(tools, list) and tools:
            first_tool = tools[0]
            if isinstance(first_tool, dict):
                return first_tool.get("name") or first_tool.get("vendor"), first_tool.get("version")
            return None, None
        if isinstance(tools, dict):
            # CycloneDX 1.5+ tools object
            components = tools.get("components", [])
            if components:
                return components[0].get("name"), components[0].get("version")
        return None, None

    @staticmethod
    def _build_cyclonedx_deps_graph(
        dependencies_map: List[Dict[str, Any]],
    ) -> Tuple[Dict[str, list], Dict[str, list], set]:
        """Build forward/reverse cyclonedx dep graphs and the transitive ref set."""
        deps_graph: Dict[str, list] = {}
        reverse_deps_graph: Dict[str, list] = {}
        all_transitive_refs: set = set()

        for dep_entry in dependencies_map:
            ref = dep_entry.get("ref", "")
            depends_on = dep_entry.get("dependsOn", [])
            deps_graph[ref] = depends_on
            for transitive_ref in depends_on:
                all_transitive_refs.add(transitive_ref)
                reverse_deps_graph.setdefault(transitive_ref, []).append(ref)

        return deps_graph, reverse_deps_graph, all_transitive_refs

    @staticmethod
    def _resolve_cyclonedx_direct_refs(
        deps_graph: Dict[str, list], all_transitive_refs: set, main_bom_ref: Optional[str]
    ) -> set:
        """Resolve the set of direct refs given the dep graph and main component."""
        if main_bom_ref and main_bom_ref in deps_graph:
            return set(deps_graph[main_bom_ref])
        # Fallback when the SBOM's metadata.component bom-ref does not match any graph node
        # (varies by SBOM tool). The root(s) are the refs nothing depends on; the DIRECT
        # dependencies are those roots' children — NOT the roots themselves (a root is the
        # application/component, not one of its dependencies). Returning the roots marked
        # every real dependency transitive.
        roots = {ref for ref in deps_graph if ref not in all_transitive_refs and ref != main_bom_ref}
        direct: set = set()
        for root in roots:
            direct.update(deps_graph.get(root, []))
        # Degenerate graph (roots have no recorded children): treat the roots as direct so
        # we don't mark everything transitive.
        return direct or roots

    def _parse_cyclonedx(self, sbom: Dict[str, Any], result: ParsedSBOM) -> None:
        """Parse CycloneDX format SBOM."""

        metadata = sbom.get("metadata", {})
        tool_name, tool_version = self._extract_cyclonedx_tool(metadata.get("tools", []))
        if tool_name is not None:
            result.tool_name = tool_name
        if tool_version is not None:
            result.tool_version = tool_version

        result.created_at = metadata.get("timestamp")

        # Source/Subject info (global SBOM source)
        global_source_type, source_target = self._extract_cyclonedx_source(metadata)
        result.source_type = global_source_type
        result.source_target = source_target

        # Get the main component bom-ref (root of dependency tree)
        main_bom_ref = metadata.get("component", {}).get("bom-ref")

        # Parse the dependencies array to build dependency graph
        dependencies_map = sbom.get("dependencies", [])
        deps_graph, reverse_deps_graph, all_transitive_refs = self._build_cyclonedx_deps_graph(dependencies_map)
        direct_refs = self._resolve_cyclonedx_direct_refs(deps_graph, all_transitive_refs, main_bom_ref)

        logger.debug(
            f"CycloneDX dependency analysis: has_graph={bool(dependencies_map)}, "
            f"main_bom_ref={main_bom_ref}, "
            f"direct_refs={len(direct_refs)}, transitive_refs={len(all_transitive_refs)}, "
            f"reverse_deps_entries={len(reverse_deps_graph)}"
        )

        components = sbom.get("components", [])
        result.crypto_assets = parse_crypto_components(components)

        for comp in components:
            if comp.get("type") == "cryptographic-asset":
                continue
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
                source_type = SOURCE_TYPE_IMAGE
                source_target = f"{comp_name}:{comp_version}" if comp_version else comp_name
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
        global_source_type: Optional[str],
    ) -> Optional[str]:
        """Determine a component's likely source: image, application, file, or None."""
        purl_type = get_purl_type(purl)
        effective_type = (purl_type or pkg_type or "").lower()

        if effective_type in OS_PACKAGE_TYPES:
            if layer_digest or global_source_type == SOURCE_TYPE_IMAGE:
                return SOURCE_TYPE_IMAGE

        if effective_type in APP_PACKAGE_TYPES:
            return SOURCE_TYPE_APPLICATION

        if layer_digest:
            return SOURCE_TYPE_IMAGE

        return global_source_type

    def _construct_purl(self, pkg_type: str, name: str, version: str, group: Optional[str] = None) -> str:
        """Construct a PURL from component metadata."""
        type_mapping = {
            "library": "generic",
            "application": "generic",
            "container": "oci",
            "operating-system": "generic",
            "device": "generic",
            "firmware": "generic",
            "file": "generic",
            "framework": "generic",
        }
        purl_type = type_mapping.get(pkg_type, pkg_type)

        if group:
            return f"pkg:{purl_type}/{group}/{name}@{version}"
        else:
            return f"pkg:{purl_type}/{name}@{version}"

    @staticmethod
    def _resolve_cyclonedx_directness(
        check_ref: Optional[str],
        direct_refs: Optional[set],
        all_transitive_refs: Optional[set],
    ) -> Tuple[bool, bool]:
        """Return (direct, direct_inferred) for a cyclonedx component."""
        has_dependency_graph = bool(direct_refs) or bool(all_transitive_refs)
        if not (has_dependency_graph and direct_refs is not None and all_transitive_refs is not None):
            # No dependency graph - assume top-level direct, mark as inferred
            return True, True
        if check_ref in direct_refs or (check_ref not in all_transitive_refs and direct_refs):
            return True, False
        return False, False

    _LAYER_DIGEST_PROPS = ("trivy:LayerDigest", "aquasecurity:trivy:LayerDigest")
    _LAYER_DIFFID_PROP = "aquasecurity:trivy:LayerDiffID"
    _FOUND_BY_PROP = "syft:package:foundBy"

    @classmethod
    def _classify_cyclonedx_property(
        cls,
        prop_name: str,
        prop_value: str,
        current_layer: Optional[str],
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Return (layer_digest_update, found_by_update, location_update) for a single property.

        Each item is either None (no update) or the new value to record.
        Caller is responsible for honouring "first wins" semantics where applicable.
        """
        if prop_name in cls._LAYER_DIGEST_PROPS:
            return prop_value, None, None
        if prop_name == cls._LAYER_DIFFID_PROP:
            return (prop_value if not current_layer else None), None, None
        if prop_name == cls._FOUND_BY_PROP:
            return None, prop_value, None
        lower = prop_name.lower()
        if ("location" in lower or "path" in lower) and prop_value:
            return None, None, prop_value
        return None, None, None

    @classmethod
    def _extract_cyclonedx_properties(
        cls,
        comp: Dict[str, Any],
    ) -> Tuple[Optional[str], Optional[str], List[str], Dict[str, str]]:
        """Extract (layer_digest, found_by, locations, properties) from comp."""
        layer_digest: Optional[str] = None
        found_by: Optional[str] = None
        locations: List[str] = []
        properties: Dict[str, str] = {}

        for prop in comp.get("properties", []):
            prop_name = prop.get("name", "")
            prop_value = prop.get("value", "")
            if prop_name and prop_value:
                properties[prop_name] = prop_value

            new_layer, new_found_by, new_location = cls._classify_cyclonedx_property(
                prop_name, prop_value, layer_digest
            )
            if new_layer is not None:
                layer_digest = new_layer
            if new_found_by is not None:
                found_by = new_found_by
            if new_location is not None:
                locations.append(new_location)

        for occ in comp.get("evidence", {}).get("occurrences", []):
            loc = occ.get("location")
            if loc and loc not in locations:
                locations.append(loc)

        return layer_digest, found_by, locations, properties

    @staticmethod
    def _extract_cyclonedx_external_refs(
        external_refs: List[Dict[str, Any]],
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Return (homepage, repository_url, download_url) from externalReferences."""
        homepage: Optional[str] = None
        repository_url: Optional[str] = None
        download_url: Optional[str] = None
        for ref in external_refs:
            ref_type = ref.get("type", "").lower()
            ref_url = ref.get("url", "")
            if ref_type == "website" and not homepage:
                homepage = ref_url
            elif ref_type in ("vcs", "git") and not repository_url:
                repository_url = ref_url
            elif ref_type in ("distribution", "download") and not download_url:
                download_url = ref_url
        return homepage, repository_url, download_url

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
        component_type = comp.get("type", "library")
        group = comp.get("group")

        if not name:
            return None

        if not purl:
            purl = self._construct_purl(component_type, name, version, group)
            logger.debug(f"Constructed PURL for {name}@{version}: {purl}")

        check_ref = bom_ref or purl
        direct, direct_inferred = self._resolve_cyclonedx_directness(check_ref, direct_refs, all_transitive_refs)

        parent_components = []
        if reverse_deps_graph and check_ref in reverse_deps_graph:
            parent_components = reverse_deps_graph[check_ref]

        license_str, license_url = self._extract_cyclonedx_licenses_full(comp.get("licenses", []))

        layer_digest, found_by, locations, properties = self._extract_cyclonedx_properties(comp)

        # CycloneDX defines a single string field `cpe` (there is no `cpes` array in
        # the 1.4-1.6 spec). Read the spec field; also accept a non-standard `cpes`
        # list (dict- or string-form) as a defensive fallback.
        cpe = comp.get("cpe")
        cpes = [cpe] if cpe else []
        for c in comp.get("cpes") or []:
            val = c.get("cpe") if isinstance(c, dict) else c
            if val and val not in cpes:
                cpes.append(val)

        hashes: Dict[str, str] = {}
        for h in comp.get("hashes", []):
            alg = h.get("alg", "").lower()
            content = h.get("content", "")
            if alg and content:
                hashes[alg] = content

        homepage, repository_url, download_url = self._extract_cyclonedx_external_refs(
            comp.get("externalReferences", [])
        )

        component_type = comp.get("type", "library")
        determined_source_type = self._determine_component_source(
            purl=purl,
            pkg_type=component_type,
            layer_digest=layer_digest,
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
            direct_inferred=direct_inferred,
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

    @staticmethod
    def _classify_license_value(
        value: str, current_url: Optional[str], fallback_url: Optional[str] = None
    ) -> Tuple[Optional[str], Optional[str]]:
        """Classify a license value, returning (name_or_extracted, new_url_or_None).

        Handles whether the value is a URL (try to extract SPDX id) or a plain name.
        If a plain name has a separate fallback_url, returns that as the URL when no
        current URL is set.
        """
        if is_url(value):
            new_url = current_url or value
            extracted = extract_license_from_url(value)
            return extracted, new_url
        if not current_url and fallback_url:
            return value, fallback_url
        return value, None

    def _handle_cyclonedx_license_dict(
        self, lic: Dict[str, Any], license_names: List[str], license_url: Optional[str]
    ) -> Optional[str]:
        """Handle a single CycloneDX license-dict entry; returns possibly updated url."""
        # Could be license object or expression
        if "license" in lic:
            inner = lic["license"]
            if isinstance(inner, dict):
                name_or_id = inner.get("id") or inner.get("name", "")
                name, new_url = self._classify_license_value(name_or_id, license_url, inner.get("url"))
                if name:
                    license_names.append(name)
                if new_url and not license_url:
                    license_url = new_url
            return license_url

        for key in ("expression", "id", "name"):
            if key in lic:
                value = lic[key]
                fallback = lic.get("url") if key in ("id", "name") else None
                name, new_url = self._classify_license_value(value, license_url, fallback)
                if name:
                    license_names.append(name)
                if new_url and not license_url:
                    license_url = new_url
                return license_url
        return license_url

    def _extract_cyclonedx_licenses_full(self, licenses: List[Any]) -> Tuple[str, Optional[str]]:
        """Extract license string and URL from CycloneDX license array."""
        if not licenses:
            return "", None

        license_names: List[str] = []
        license_url: Optional[str] = None

        for lic in licenses:
            if isinstance(lic, dict):
                license_url = self._handle_cyclonedx_license_dict(lic, license_names, license_url)
            elif isinstance(lic, str):
                name, new_url = self._classify_license_value(lic, license_url)
                if name:
                    license_names.append(name)
                if new_url and not license_url:
                    license_url = new_url

        return ", ".join(filter(None, license_names)), license_url

    _SYFT_APP_PACKAGE_TYPES = (
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
    )
    _SYFT_KNOWN_SOURCE_TYPES = (
        SOURCE_TYPE_IMAGE,
        SOURCE_TYPE_DIRECTORY,
        SOURCE_TYPE_FILE,
        SOURCE_TYPE_FILE_SYSTEM,
    )

    @classmethod
    def _resolve_syft_source(cls, source: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """Return (source_type, source_target) parsed from a syft source dict."""
        source_type_raw = source.get("type", "")
        if source_type_raw not in cls._SYFT_KNOWN_SOURCE_TYPES:
            return None, None
        if source_type_raw == SOURCE_TYPE_IMAGE:
            metadata = source.get("metadata", {})
            target = source.get("target", "") or metadata.get("userInput", "") or metadata.get("imageID", "")
            return SOURCE_TYPE_IMAGE, target
        return source_type_raw, source.get("target", "")

    @staticmethod
    def _build_syft_relationship_graph(
        relationships: List[Dict[str, Any]], source_id: str
    ) -> Tuple[set, set, Dict[str, list]]:
        """Build (direct_artifact_ids, all_child_ids, reverse_deps_graph) for syft."""
        direct_artifact_ids: set = set()
        all_child_ids: set = set()
        reverse_deps_graph: Dict[str, list] = {}
        direct_rel_types = ("contains", "dependency-of", "depends-on")

        for rel in relationships:
            parent = rel.get("parent", "")
            child = rel.get("child", "")
            rel_type = rel.get("type", "")

            if child:
                all_child_ids.add(child)
                reverse_deps_graph.setdefault(child, [])
                if parent and parent != source_id:
                    reverse_deps_graph[child].append(parent)

            if parent == source_id and rel_type in direct_rel_types:
                direct_artifact_ids.add(child)

        return direct_artifact_ids, all_child_ids, reverse_deps_graph

    @classmethod
    def _syft_image_fallback_direct_ids(cls, artifacts: List[Dict[str, Any]]) -> set:
        """Heuristic: treat application-level package artifacts as direct in images."""
        return {artifact.get("id") for artifact in artifacts if artifact.get("type", "") in cls._SYFT_APP_PACKAGE_TYPES}

    def _parse_syft(self, sbom: Dict[str, Any], result: ParsedSBOM) -> None:
        """Parse Syft JSON format SBOM."""

        descriptor = sbom.get("descriptor", {})
        result.tool_name = descriptor.get("name", "syft")
        result.tool_version = descriptor.get("version")

        source = sbom.get("source", {})
        source_id = source.get("id", "")
        source_type, source_target = self._resolve_syft_source(source)
        if source_type is not None:
            result.source_type = source_type
            result.source_target = source_target

        artifacts = sbom.get("artifacts", [])
        relationships = sbom.get("artifactRelationships", [])

        direct_artifact_ids, all_child_ids, reverse_deps_graph = self._build_syft_relationship_graph(
            relationships, source_id
        )

        if not direct_artifact_ids and result.source_type == SOURCE_TYPE_IMAGE:
            direct_artifact_ids = self._syft_image_fallback_direct_ids(artifacts)

        logger.debug(
            f"Syft relationship analysis: {len(direct_artifact_ids)} direct, "
            f"{len(all_child_ids)} total children from {len(relationships)} relationships"
        )

        inferred = not bool(relationships)

        for artifact in artifacts:
            artifact_id = artifact.get("id", "")
            is_direct = inferred or (artifact_id in direct_artifact_ids)
            parent_components = reverse_deps_graph.get(artifact_id, [])

            parsed = self._parse_syft_artifact(
                artifact,
                result.source_type,
                result.source_target,
                is_direct,
                inferred,
                parent_components,
            )
            if parsed:
                result.dependencies.append(parsed)
            else:
                result.skipped_components += 1

    @staticmethod
    def _extract_syft_locations(
        location_entries: List[Dict[str, Any]],
    ) -> Tuple[List[str], Optional[str]]:
        """Return (locations, first_layer_digest) from a syft location list."""
        locations: List[str] = []
        layer_digest: Optional[str] = None
        for loc in location_entries:
            path = loc.get("path", "")
            access_path = loc.get("accessPath", "")
            effective_path = access_path if access_path and access_path != path else path
            if effective_path and effective_path not in locations:
                locations.append(effective_path)
            layer_id = loc.get("layerID", "")
            if layer_id and not layer_digest:
                layer_digest = layer_id
        return locations, layer_digest

    @staticmethod
    def _extract_syft_author(metadata: Dict[str, Any]) -> Optional[str]:
        """Extract author/maintainer string from syft metadata."""
        authors = metadata.get("authors")
        if authors:
            if isinstance(authors, list):
                return ", ".join(authors)
            return str(authors)
        return metadata.get("author") or metadata.get("maintainer")

    @staticmethod
    def _extract_syft_hashes(metadata: Dict[str, Any]) -> Dict[str, str]:
        """Extract hashes from syft metadata (direct fields + digests array)."""
        hashes: Dict[str, str] = {}
        for hash_type in ("md5", "sha1", "sha256", "sha512"):
            if metadata.get(hash_type):
                hashes[hash_type] = metadata[hash_type]
        for digest in metadata.get("digests", []):
            alg = digest.get("algorithm", "").lower()
            value = digest.get("value", "")
            if alg and value:
                hashes[alg] = value
        return hashes

    @staticmethod
    def _resolve_syft_direct(is_direct: bool, metadata: Dict[str, Any]) -> bool:
        """Combine relationship-based and metadata-flag directness."""
        if is_direct:
            return True
        if metadata and (metadata.get("directDependency") or metadata.get("direct")):
            return True
        return False

    def _parse_syft_artifact(
        self,
        artifact: Dict[str, Any],
        source_type: Optional[str],
        source_target: Optional[str],
        is_direct: bool = False,
        direct_inferred: bool = False,
        parent_components: Optional[List[str]] = None,
    ) -> Optional[ParsedDependency]:
        """Parse a single Syft artifact with all available fields."""

        purl = artifact.get("purl")
        name = artifact.get("name")
        version = artifact.get("version", "unknown")
        pkg_type = artifact.get("type", "unknown")

        if parent_components is None:
            parent_components = []

        if not name:
            return None

        if not purl:
            purl = self._construct_purl(pkg_type, name, version)
            logger.debug(f"Constructed PURL for Syft artifact {name}@{version}: {purl}")

        license_str, license_url = self._extract_syft_licenses_full(artifact.get("licenses", []))
        locations, layer_digest = self._extract_syft_locations(artifact.get("locations", []))
        # Syft JSON schema < 16.0 emits `cpes` as a list of plain strings; newer
        # releases use a list of dicts ({"cpe": "..."}). Handle both so a legacy
        # SBOM does not crash the artifact loop and silently drop dependencies.
        cpes = [(c.get("cpe") if isinstance(c, dict) else c) for c in artifact.get("cpes") or [] if c]
        cpes = [c for c in cpes if c]
        found_by = artifact.get("foundBy")
        pkg_type = artifact.get("type", "unknown")

        metadata = artifact.get("metadata", {})
        direct = self._resolve_syft_direct(is_direct, metadata)
        description = metadata.get("description") or metadata.get("summary")
        author = self._extract_syft_author(metadata)
        homepage = metadata.get("homepage") or metadata.get("url")
        repository_url = metadata.get("source") or metadata.get("repository")
        hashes = self._extract_syft_hashes(metadata)

        properties = {
            key: str(metadata[key])
            for key in ("language", "origin", "architecture", "filesAnalyzed")
            if metadata.get(key)
        }

        # Determine component-specific source type
        determined_source_type = self._determine_component_source(
            purl=purl,
            pkg_type=pkg_type,
            layer_digest=layer_digest,
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
            direct_inferred=direct_inferred,
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

    @staticmethod
    def _syft_license_dict_url(lic: Dict[str, Any]) -> Optional[str]:
        """Extract a dedicated license URL from a syft license dict ('url'/'urls')."""
        for url_key in ("url", "urls"):
            url_val = lic.get(url_key)
            if not url_val:
                continue
            if isinstance(url_val, list):
                return str(url_val[0]) if url_val else None
            return str(url_val) if url_val else None
        return None

    def _handle_syft_license_dict(
        self, lic: Dict[str, Any], license_names: List[str], license_url: Optional[str]
    ) -> Optional[str]:
        """Handle a single syft license-dict entry; returns possibly updated url."""
        value = lic.get("value") or lic.get("spdxExpression") or lic.get("type", "")
        if value:
            name, new_url = self._classify_license_value(value, license_url)
            if name:
                license_names.append(name)
            if new_url and not license_url:
                license_url = new_url

        if not license_url:
            dedicated_url = self._syft_license_dict_url(lic)
            if dedicated_url:
                license_url = dedicated_url
        return license_url

    def _extract_syft_licenses_full(self, licenses: List[Any]) -> Tuple[str, Optional[str]]:
        """Extract license string and URL from Syft license array."""
        if not licenses:
            return "", None

        license_names: List[str] = []
        license_url: Optional[str] = None

        for lic in licenses:
            if isinstance(lic, dict):
                license_url = self._handle_syft_license_dict(lic, license_names, license_url)
            elif isinstance(lic, str):
                name, new_url = self._classify_license_value(lic, license_url)
                if name:
                    license_names.append(name)
                if new_url and not license_url:
                    license_url = new_url

        # Deduplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        for lic in license_names:
            if lic not in seen:
                seen.add(lic)
                unique.append(lic)

        return ", ".join(unique), license_url

    def _build_spdx_dependency_graph(
        self, relationships: List[Dict[str, Any]], doc_spdx_id: str
    ) -> Tuple[set, Dict[str, list]]:
        """
        Build SPDX dependency-graph data used to classify direct vs transitive deps.

        In the canonical SPDX layout (e.g. a GitHub SBOM export) the document
        DESCRIBES a root package (the application/repo); that root's DEPENDS_ON
        children are the DIRECT dependencies and the root package itself is NOT a
        dependency. Only when a DESCRIBES target has no DEPENDS_ON children (minimal
        SBOMs) is the described package itself the direct dep. Packages the document
        points at directly via CONTAINS/DEPENDS_ON are treated as direct.

        Returns:
            Tuple of (direct_package_ids, reverse_deps_graph)
        """
        described_roots: set = set()  # application roots (DOCUMENT DESCRIBES ...)
        doc_direct_targets: set = set()  # packages the DOCUMENT points at directly
        forward_deps: Dict[str, list] = {}  # element -> [children] via DEPENDS_ON
        all_dependency_targets: set = set()  # every DEPENDS_ON target (transitive candidates)
        packages_with_deps: set = set()  # elements that declare DEPENDS_ON edges
        reverse_deps_graph: Dict[str, list] = {}

        for rel in relationships:
            rel_type = rel.get("relationshipType", "")
            element_id = rel.get("spdxElementId", "")
            related_id = rel.get("relatedSpdxElement", "")

            if element_id == doc_spdx_id:
                if rel_type in ("DESCRIBES", "DOCUMENT_DESCRIBES"):
                    described_roots.add(related_id)
                elif rel_type in ("CONTAINS", "DEPENDS_ON"):
                    doc_direct_targets.add(related_id)

            if rel_type == "DEPENDS_ON":
                forward_deps.setdefault(element_id, []).append(related_id)
                all_dependency_targets.add(related_id)
                packages_with_deps.add(element_id)
                reverse_deps_graph.setdefault(related_id, []).append(element_id)

        # Direct deps = (a) packages the document points at directly, plus (b) the
        # DEPENDS_ON children of each described root (or the root itself if it has none).
        direct_package_ids: set = set(doc_direct_targets)
        for root in described_roots:
            children = forward_deps.get(root)
            if children:
                direct_package_ids.update(children)
            else:
                direct_package_ids.add(root)

        # Fallback for SBOMs with no document-level roots: infer roots as packages that
        # have deps but are not themselves depended upon, and take their children.
        if not direct_package_ids and packages_with_deps:
            for root in packages_with_deps - all_dependency_targets:
                direct_package_ids.update(forward_deps.get(root, []))

        return direct_package_ids, reverse_deps_graph

    def _parse_spdx(self, sbom: Dict[str, Any], result: ParsedSBOM) -> None:
        """Parse SPDX format SBOM."""

        result.tool_name = "spdx"
        result.format_version = sbom.get("spdxVersion")
        result.created_at = sbom.get("creationInfo", {}).get("created")

        relationships = sbom.get("relationships", [])
        doc_spdx_id = sbom.get("SPDXID", "SPDXRef-DOCUMENT")

        direct_package_ids, reverse_deps_graph = self._build_spdx_dependency_graph(relationships, doc_spdx_id)

        packages = sbom.get("packages", [])
        inferred = not bool(relationships)

        for pkg in packages:
            pkg_spdx_id = pkg.get("SPDXID", "")

            is_direct = inferred or pkg_spdx_id in direct_package_ids

            parent_components = reverse_deps_graph.get(pkg_spdx_id, [])

            parsed = self._parse_spdx_package(pkg, is_direct, inferred, parent_components)
            if parsed:
                result.dependencies.append(parsed)
            else:
                result.skipped_components += 1

    _SPDX_DOWNLOAD_LOC_TYPE_MAP = (
        (("npmjs.org", "registry.npmjs"), "npm"),
        (("pypi.org", "pypi.python.org"), "pypi"),
        (("maven", "mvnrepository"), "maven"),
        (("crates.io",), "cargo"),
        (("rubygems",), "gem"),
    )

    _SPDX_PURL_PREFIX_TYPE_MAP = {
        "pkg:npm/": "npm",
        "pkg:pypi/": "python",
        "pkg:maven/": "java",
        "pkg:golang/": "go-module",
        "pkg:deb/": "deb",
        "pkg:rpm/": "rpm",
        "pkg:apk/": "apk",
        "pkg:cargo/": "cargo",
        "pkg:nuget/": "nuget",
        "pkg:gem/": "gem",
    }

    @staticmethod
    def _extract_spdx_external_refs(
        external_refs: List[Dict[str, Any]],
    ) -> Tuple[Optional[str], List[str]]:
        """Return (purl, cpes) from an SPDX externalRefs list."""
        purl: Optional[str] = None
        cpes: List[str] = []
        for ref in external_refs:
            ref_type = ref.get("referenceType", "")
            locator = ref.get("referenceLocator", "")
            if ref_type == "purl" and not purl:
                purl = locator
            elif ref_type in ("cpe22Type", "cpe23Type") and locator:
                cpes.append(locator)
        return purl, cpes

    @classmethod
    def _infer_spdx_pkg_type_from_download(cls, download_loc: str) -> str:
        """Infer a package type from an SPDX downloadLocation hint."""
        for needles, pkg_type in cls._SPDX_DOWNLOAD_LOC_TYPE_MAP:
            if any(n in download_loc for n in needles):
                return pkg_type
        return "generic"

    @classmethod
    def _spdx_pkg_type_from_purl(cls, purl: Optional[str]) -> str:
        """Map an SPDX-derived PURL to a normalized pkg_type."""
        if not purl:
            return "unknown"
        for prefix, pkg_type in cls._SPDX_PURL_PREFIX_TYPE_MAP.items():
            if purl.startswith(prefix):
                return pkg_type
        return "unknown"

    @staticmethod
    def _resolve_spdx_license(pkg: Dict[str, Any]) -> Tuple[str, Optional[str]]:
        """Extract (license_str, license_url) from SPDX licenseConcluded/Declared."""
        license_concluded = pkg.get("licenseConcluded", "")
        license_declared = pkg.get("licenseDeclared", "")
        license_str = license_concluded if license_concluded != "NOASSERTION" else license_declared
        if license_str == "NOASSERTION":
            license_str = ""

        license_url: Optional[str] = None
        if is_url(license_str):
            license_url = license_str
            extracted = extract_license_from_url(license_str)
            license_str = extracted if extracted else ""
        return license_str, license_url

    @staticmethod
    def _resolve_spdx_originator(
        pkg: Dict[str, Any],
    ) -> Tuple[Optional[str], Optional[str]]:
        """Extract (author, publisher) from SPDX originator/supplier fields."""
        author: Optional[str] = None
        publisher: Optional[str] = None

        originator = pkg.get("originator")
        if originator and originator != "NOASSERTION":
            if originator.startswith(SPDX_ORGANIZATION_PREFIX):
                publisher = originator.replace(SPDX_ORGANIZATION_PREFIX, "").strip()
            elif originator.startswith("Person:"):
                author = originator.replace("Person:", "").strip()
            else:
                author = originator

        supplier = pkg.get("supplier")
        if supplier and supplier != "NOASSERTION" and not publisher:
            if supplier.startswith(SPDX_ORGANIZATION_PREFIX):
                publisher = supplier.replace(SPDX_ORGANIZATION_PREFIX, "").strip()
        return author, publisher

    @staticmethod
    def _build_spdx_properties(pkg: Dict[str, Any]) -> Dict[str, str]:
        """Build the SPDX-specific 'properties' dict."""
        properties: Dict[str, str] = {}
        if pkg.get("filesAnalyzed") is not None:
            properties["filesAnalyzed"] = str(pkg["filesAnalyzed"])
        if pkg.get("packageFileName"):
            properties["packageFileName"] = pkg["packageFileName"]
        if pkg.get("sourceInfo"):
            properties["sourceInfo"] = pkg["sourceInfo"]
        copyright_text = pkg.get("copyrightText")
        if copyright_text and copyright_text != "NOASSERTION":
            properties["copyright"] = copyright_text
        return properties

    @staticmethod
    def _extract_spdx_hashes(pkg: Dict[str, Any]) -> Dict[str, str]:
        """Extract a hash map from an SPDX package's checksums array."""
        hashes: Dict[str, str] = {}
        for checksum in pkg.get("checksums", []):
            alg = checksum.get("algorithm", "").lower()
            value = checksum.get("checksumValue", "")
            if alg and value:
                hashes[alg] = value
        return hashes

    def _parse_spdx_package(
        self,
        pkg: Dict[str, Any],
        is_direct: bool = False,
        direct_inferred: bool = False,
        parent_components: Optional[List[str]] = None,
    ) -> Optional[ParsedDependency]:
        """Parse a single SPDX package with all available fields."""

        name = pkg.get("name")
        version = pkg.get("versionInfo", "unknown")

        if not name:
            return None

        if parent_components is None:
            parent_components = []

        purl, cpes = self._extract_spdx_external_refs(pkg.get("externalRefs", []))

        if not purl:
            inferred_type = self._infer_spdx_pkg_type_from_download(pkg.get("downloadLocation", ""))
            purl = self._construct_purl(inferred_type, name, version)
            logger.debug(f"Constructed PURL for SPDX package {name}@{version}: {purl}")

        license_str, license_url = self._resolve_spdx_license(pkg)
        pkg_type = self._spdx_pkg_type_from_purl(purl)
        hashes = self._extract_spdx_hashes(pkg)

        homepage = pkg.get("homepage")
        if homepage == "NOASSERTION":
            homepage = None

        download_url = pkg.get("downloadLocation")
        if download_url in ("NOASSERTION", "NONE"):
            download_url = None

        author, publisher = self._resolve_spdx_originator(pkg)
        properties = self._build_spdx_properties(pkg)

        # Determine source type based on package type
        determined_source_type = self._determine_component_source(
            purl=purl,
            pkg_type=pkg_type,
            layer_digest=None,  # SPDX doesn't have layer info
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
            direct_inferred=direct_inferred,
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
