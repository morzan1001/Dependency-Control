"""Unified parsing of CycloneDX, SPDX, and Syft JSON SBOMs into a common representation."""

import logging
import re
from typing import Any
from urllib.parse import quote, urlparse

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
from app.services.analyzers.purl_utils import get_purl_type, parse_purl
from app.services.cbom_parser import parse_crypto_components

logger = logging.getLogger(__name__)

# SBOMs are untrusted input; without a cap, hostile nesting raises RecursionError
# and the format handler degrades the whole SBOM to zero components.
MAX_COMPONENT_NESTING_DEPTH = 100


def is_url(value: str) -> bool:
    """Check if a string is a URL."""
    if not value:
        return False
    try:
        result = urlparse(value)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
        return False


def extract_license_from_url(url: str) -> str | None:
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
    def _detect_cyclonedx(sbom: dict[str, Any]) -> tuple[SBOMFormat, str | None] | None:
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
    def _detect_spdx(sbom: dict[str, Any]) -> tuple[SBOMFormat, str | None] | None:
        """Try to detect SPDX format."""
        if sbom.get("spdxVersion"):
            return SBOMFormat.SPDX, sbom.get("spdxVersion")

        if "SPDX" in sbom.get("$schema", ""):
            return SBOMFormat.SPDX, None

        return None

    @staticmethod
    def _detect_syft(sbom: dict[str, Any]) -> tuple[SBOMFormat, str | None] | None:
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

    def detect_format(self, sbom: dict[str, Any]) -> tuple[SBOMFormat, str | None]:
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

    def parse(self, sbom: dict[str, Any]) -> ParsedSBOM:
        """Parse an SBOM and return normalized representation."""

        format_type, version = self.detect_format(sbom)

        result = ParsedSBOM(format=format_type, format_version=version)

        # A document-level failure must propagate: swallowing it would report an
        # empty parse as success, and persistence would then replace the scan's
        # previous dependency set with nothing.
        if format_type == SBOMFormat.UNKNOWN:
            logger.warning("Unknown SBOM format, attempting best-effort parsing")
            # Each attempt gets a fresh result so a failed handler cannot leave partial
            # dependencies or counters behind for the next one to build on.
            last_error: Exception | None = None
            handler_completed = False
            for handler in self.format_handlers.values():
                candidate = ParsedSBOM(format=format_type, format_version=version)
                try:
                    handler(sbom, candidate)
                except Exception as e:
                    last_error = e
                    logger.debug("Best-effort SBOM parse attempt failed, trying next handler", exc_info=True)
                    continue
                handler_completed = True
                if candidate.dependencies:
                    result = candidate
                    break
            if not handler_completed and last_error is not None:
                raise last_error
        else:
            format_handler = self.format_handlers.get(format_type)
            if format_handler is not None:
                try:
                    format_handler(sbom, result)
                except Exception:
                    logger.exception("Error parsing %s SBOM", format_type.value)
                    raise

        self._merge_duplicate_dependencies(result)

        result.total_components = len(result.dependencies) + result.skipped_components + result.merged_components
        result.parsed_components = len(result.dependencies)

        return result

    @staticmethod
    def _count_skipped(result: ParsedSBOM, reason: str, count: int = 1) -> None:
        if count <= 0:
            return
        result.skipped_components += count
        result.skipped_reasons[reason] = result.skipped_reasons.get(reason, 0) + count

    # Placeholder tokens generators emit when they could not determine a version.
    _PLACEHOLDER_VERSIONS = frozenset({"", "unknown", "noassertion", "none"})

    @classmethod
    def _normalize_version(cls, raw: Any) -> str:
        if raw is None or not isinstance(raw, (str, int, float)):
            return "unknown"
        version = str(raw).strip()
        return "unknown" if version.lower() in cls._PLACEHOLDER_VERSIONS else version

    @staticmethod
    def _merge_duplicate_dependencies(result: ParsedSBOM) -> None:
        """Collapse (name, version, purl) duplicates so the unique DB index doesn't silently drop them."""
        by_key: dict[tuple[str, str, str | None], ParsedDependency] = {}
        for dep in result.dependencies:
            key = (dep.name, dep.version, dep.purl)
            kept = by_key.get(key)
            if kept is None:
                by_key[key] = dep
                continue
            for attr in ("locations", "parent_components", "cpes"):
                kept_values = getattr(kept, attr)
                kept_values.extend(v for v in getattr(dep, attr) if v not in kept_values)
            for alg, digest in dep.hashes.items():
                kept.hashes.setdefault(alg, digest)
            kept.layer_digest = kept.layer_digest or dep.layer_digest
            kept.found_by = kept.found_by or dep.found_by
            # Graph-confirmed directness beats guesses; direct anywhere in the SBOM wins.
            if kept.direct_inferred and not dep.direct_inferred:
                kept.direct, kept.direct_inferred = dep.direct, False
            elif kept.direct_inferred == dep.direct_inferred:
                kept.direct = kept.direct or dep.direct
            result.merged_components += 1
        result.dependencies = list(by_key.values())

    @staticmethod
    def _extract_cyclonedx_tool(tools: Any) -> tuple[str | None, str | None]:
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
        dependencies_map: list[dict[str, Any]],
    ) -> tuple[dict[str, list], dict[str, list], set]:
        """Build forward/reverse cyclonedx dep graphs and the transitive ref set."""
        deps_graph: dict[str, list] = {}
        reverse_deps_graph: dict[str, list] = {}
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
        deps_graph: dict[str, list], all_transitive_refs: set, main_bom_ref: str | None
    ) -> tuple[set, bool]:
        """Resolve (direct_refs, inferred) given the dep graph and main component."""
        if main_bom_ref and main_bom_ref in deps_graph:
            return set(deps_graph[main_bom_ref]), False
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
        return direct or roots, True

    @classmethod
    def _flatten_cyclonedx_components(cls, components: Any, depth: int = 0) -> tuple[list[dict[str, Any]], int, int]:
        """Flatten nested components; returns (flat, depth_skipped, malformed) counting dropped entries."""
        flat: list[dict[str, Any]] = []
        depth_skipped = 0
        malformed = 0
        for comp in components if isinstance(components, list) else []:
            if not isinstance(comp, dict):
                malformed += 1
                continue
            if depth >= MAX_COMPONENT_NESTING_DEPTH:
                depth_skipped += cls._count_component_subtree(comp)
                continue
            flat.append(comp)
            nested, nested_skipped, nested_malformed = cls._flatten_cyclonedx_components(
                comp.get("components"), depth + 1
            )
            flat.extend(nested)
            depth_skipped += nested_skipped
            malformed += nested_malformed
        return flat, depth_skipped, malformed

    @staticmethod
    def _count_component_subtree(comp: dict[str, Any]) -> int:
        count = 0
        stack = [comp]
        while stack:
            node = stack.pop()
            count += 1
            children = node.get("components")
            if isinstance(children, list):
                stack.extend(child for child in children if isinstance(child, dict))
        return count

    # CycloneDX component types that are never software dependencies.
    _NON_DEPENDENCY_COMPONENT_TYPES = frozenset({"device", "device-driver", "data", "firmware"})

    def _parse_cyclonedx(self, sbom: dict[str, Any], result: ParsedSBOM) -> None:
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
        direct_refs, direct_refs_inferred = self._resolve_cyclonedx_direct_refs(
            deps_graph, all_transitive_refs, main_bom_ref
        )

        logger.debug(
            f"CycloneDX dependency analysis: has_graph={bool(dependencies_map)}, "
            f"main_bom_ref={main_bom_ref}, "
            f"direct_refs={len(direct_refs)}, transitive_refs={len(all_transitive_refs)}, "
            f"reverse_deps_entries={len(reverse_deps_graph)}"
        )

        # cyclonedx-npm/-maven nest sub-dependencies in components[].components[].
        components, depth_skipped, malformed = self._flatten_cyclonedx_components(sbom.get("components", []))
        self._count_skipped(result, "nesting-depth", depth_skipped)
        self._count_skipped(result, "malformed", malformed)
        if depth_skipped:
            logger.warning(
                "CycloneDX components nested deeper than %d levels; skipped %d component(s)",
                MAX_COMPONENT_NESTING_DEPTH,
                depth_skipped,
            )
        result.crypto_assets = parse_crypto_components(components)

        main_component = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
        main_refs = {ref for ref in (main_component.get("bom-ref"), main_component.get("purl")) if ref}

        for comp in components:
            comp_type = comp.get("type")
            if comp_type == "cryptographic-asset":
                # Parsed into crypto_assets, not dependencies; still counted.
                self._count_skipped(result, "cryptographic-asset")
                continue
            if comp_type == "file":
                # File-catalog entries (e.g. syft filesystem scans) aren't dependencies.
                self._count_skipped(result, "file")
                continue
            if comp_type in self._NON_DEPENDENCY_COMPONENT_TYPES:
                self._count_skipped(result, "non-dependency")
                continue
            if main_refs and (comp.get("bom-ref") in main_refs or comp.get("purl") in main_refs):
                # The SBOM's own subject repeated in the component list is not a dependency.
                self._count_skipped(result, "root-component")
                continue
            try:
                parsed = self._parse_cyclonedx_component(
                    comp,
                    global_source_type,
                    source_target,
                    direct_refs,
                    all_transitive_refs,
                    reverse_deps_graph,
                    direct_refs_inferred,
                )
            except Exception:
                logger.warning("Skipping malformed CycloneDX component %r", comp.get("name"), exc_info=True)
                self._count_skipped(result, "parse-error")
                continue
            if parsed:
                result.dependencies.append(parsed)
            else:
                self._count_skipped(result, "unidentifiable")

    def _extract_cyclonedx_source(self, metadata: dict[str, Any]) -> tuple[str | None, str | None]:
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
        purl: str | None,
        pkg_type: str,
        layer_digest: str | None,
        global_source_type: str | None,
    ) -> str | None:
        """Determine a component's likely source: image, application, file, or None."""
        purl_type = get_purl_type(purl)
        effective_type = (purl_type or pkg_type or "").lower()

        if effective_type in OS_PACKAGE_TYPES and (layer_digest or global_source_type == SOURCE_TYPE_IMAGE):
            return SOURCE_TYPE_IMAGE

        if effective_type in APP_PACKAGE_TYPES:
            return SOURCE_TYPE_APPLICATION

        if layer_digest:
            return SOURCE_TYPE_IMAGE

        return global_source_type

    def _construct_purl(self, pkg_type: str, name: str, version: str, group: str | None = None) -> str:
        """Construct a PURL from component metadata; segments are encoded so names with spaces stay legal PURLs."""
        type_mapping = {
            "library": "generic",
            "application": "generic",
            "container": "oci",
            "binary": "generic",
            "framework": "generic",
        }
        purl_type = type_mapping.get(pkg_type, pkg_type)

        namespace = f"{quote(str(group), safe='')}/" if group else ""
        return f"pkg:{purl_type}/{namespace}{quote(str(name), safe='')}@{quote(str(version), safe='')}"

    @staticmethod
    def _resolve_cyclonedx_directness(
        check_ref: str | None,
        direct_refs: set | None,
        all_transitive_refs: set | None,
        direct_refs_inferred: bool,
    ) -> tuple[bool, bool]:
        """Return (direct, direct_inferred) for a cyclonedx component."""
        if direct_refs and check_ref in direct_refs:
            return True, direct_refs_inferred
        if all_transitive_refs and check_ref in all_transitive_refs:
            return False, False
        # The graph says nothing about this ref (or there is no graph): keep it
        # direct so inventory counts hold, but flag the guess.
        return True, True

    _LAYER_DIGEST_PROPS = ("trivy:LayerDigest", "aquasecurity:trivy:LayerDigest")
    _LAYER_DIFFID_PROP = "aquasecurity:trivy:LayerDiffID"
    _FOUND_BY_PROP = "syft:package:foundBy"
    _CPE_PROPS = ("syft:cpe23", "syft:cpe22")
    # syft:location:<N>:<field> — the layerID field is a digest, not a file path.
    _SYFT_LOCATION_PROP_PREFIX = "syft:location:"
    _SYFT_LOCATION_PROP_RE = re.compile(r"^syft:location:\d+:(\w+)$")

    @classmethod
    def _classify_cyclonedx_property(
        cls,
        prop_name: str,
        prop_value: str,
        current_layer: str | None,
    ) -> tuple[str | None, str | None, str | None]:
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
        if prop_name.startswith(cls._SYFT_LOCATION_PROP_PREFIX):
            syft_location = cls._SYFT_LOCATION_PROP_RE.match(prop_name)
            field = syft_location.group(1) if syft_location else None
            if field == "layerID":
                return (prop_value if not current_layer else None), None, None
            if field in ("path", "accessPath") and prop_value:
                return None, None, prop_value
            # Anything else (annotations:evidence etc.) describes the location
            # but is not a path.
            return None, None, None
        lower = prop_name.lower()
        if ("location" in lower or "path" in lower) and prop_value:
            return None, None, prop_value
        return None, None, None

    @classmethod
    def _extract_cyclonedx_properties(
        cls,
        comp: dict[str, Any],
    ) -> tuple[str | None, str | None, list[str], dict[str, str], list[str]]:
        """Extract (layer_digest, found_by, locations, properties, cpes) from comp."""
        layer_digest: str | None = None
        found_by: str | None = None
        locations: list[str] = []
        properties: dict[str, str] = {}
        cpes: list[str] = []

        raw_props = comp.get("properties")
        for prop in raw_props if isinstance(raw_props, list) else []:
            if not isinstance(prop, dict):
                continue
            prop_name = prop.get("name", "")
            prop_value = prop.get("value", "")
            if prop_name and prop_value:
                properties[prop_name] = prop_value

            # Repeated syft:cpe23 properties collapse in the dict above, so CPEs
            # must be collected while iterating.
            if prop_name in cls._CPE_PROPS and prop_value and prop_value not in cpes:
                cpes.append(prop_value)
                continue

            new_layer, new_found_by, new_location = cls._classify_cyclonedx_property(
                prop_name, prop_value, layer_digest
            )
            if new_layer is not None:
                layer_digest = new_layer
            if new_found_by is not None:
                found_by = new_found_by
            if new_location is not None and new_location not in locations:
                locations.append(new_location)

        evidence = comp.get("evidence")
        occurrences = evidence.get("occurrences") if isinstance(evidence, dict) else None
        for occ in occurrences if isinstance(occurrences, list) else []:
            loc = occ.get("location") if isinstance(occ, dict) else None
            if loc and loc not in locations:
                locations.append(loc)

        return layer_digest, found_by, locations, properties, cpes

    @staticmethod
    def _normalize_vcs_url(raw: str) -> str | None:
        """Normalise Maven SCM / git-remote forms to an https URL, or None if unusable."""
        value = raw.strip()
        for prefix in ("scm:git:", "scm:svn:", "scm:hg:", "scm:", "git+"):
            if value.lower().startswith(prefix):
                value = value[len(prefix) :]
        if value.startswith("git@") and ":" in value[4:]:
            host, _, path = value[4:].partition(":")
            value = f"https://{host}/{path}"
        elif value.startswith(("git://", "ssh://")):
            value = "https://" + value.split("://", 1)[1]
        if value.startswith("https://git@"):
            value = "https://" + value[len("https://git@") :]
        return value if is_url(value) else None

    @classmethod
    def _extract_cyclonedx_external_refs(
        cls,
        external_refs: list[dict[str, Any]],
    ) -> tuple[str | None, str | None, str | None]:
        """Return (homepage, repository_url, download_url) from externalReferences."""
        homepage: str | None = None
        repository_url: str | None = None
        download_url: str | None = None
        for ref in external_refs if isinstance(external_refs, list) else []:
            if not isinstance(ref, dict):
                continue
            ref_type = ref.get("type", "").lower()
            ref_url = ref.get("url", "")
            if ref_type == "website" and not homepage:
                homepage = ref_url
            elif ref_type in ("vcs", "git") and not repository_url:
                repository_url = cls._normalize_vcs_url(ref_url)
            elif ref_type in ("distribution", "download") and not download_url:
                download_url = ref_url
        return homepage, repository_url, download_url

    def _parse_cyclonedx_component(
        self,
        comp: dict[str, Any],
        global_source_type: str | None,
        source_target: str | None,
        direct_refs: set | None = None,
        all_transitive_refs: set | None = None,
        reverse_deps_graph: dict | None = None,
        direct_refs_inferred: bool = False,
    ) -> ParsedDependency | None:
        """Parse a single CycloneDX component with all available fields."""

        purl = comp.get("purl")
        name = comp.get("name")
        version = self._normalize_version(comp.get("version"))
        bom_ref = comp.get("bom-ref")
        component_type = comp.get("type", "library")
        group = comp.get("group")

        if not name:
            return None

        layer_digest, found_by, locations, properties, prop_cpes = self._extract_cyclonedx_properties(comp)

        # CycloneDX defines a single string field `cpe` (there is no `cpes` array in
        # the 1.4-1.6 spec). Read the spec field; also accept a non-standard `cpes`
        # list (dict- or string-form) as a defensive fallback, plus the syft:cpe23
        # property form syft-generated SBOMs use for their full CPE list.
        cpe = comp.get("cpe")
        cpes = [cpe] if cpe else []
        for c in list(comp.get("cpes") or []) + prop_cpes:
            val = c.get("cpe") if isinstance(c, dict) else c
            if val and val not in cpes:
                cpes.append(val)

        if not purl:
            if component_type == "operating-system":
                # OS descriptors stay (they feed base-image EOL detection) but a
                # fabricated pkg:generic id matches no vulnerability source.
                purl = None
            elif component_type == "application":
                # Binary-classifier hits: without a real purl or CPE nothing can
                # ever match them across scans or feeds.
                if not cpes:
                    return None
                purl = None
            elif version == "unknown":
                # Neither a real identifier nor a comparable version.
                return None
            else:
                purl = self._construct_purl(component_type, name, version, group)
                logger.debug(f"Constructed PURL for {name}@{version}: {purl}")

        check_ref = bom_ref or purl
        direct, direct_inferred = self._resolve_cyclonedx_directness(
            check_ref, direct_refs, all_transitive_refs, direct_refs_inferred
        )

        parent_components = []
        if reverse_deps_graph and check_ref in reverse_deps_graph:
            parent_components = reverse_deps_graph[check_ref]

        license_str, license_url = self._extract_cyclonedx_licenses_full(comp.get("licenses") or [])

        hashes: dict[str, str] = {}
        raw_hashes = comp.get("hashes")
        for h in raw_hashes if isinstance(raw_hashes, list) else []:
            if not isinstance(h, dict):
                continue
            alg = h.get("alg", "").lower()
            content = h.get("content", "")
            if alg and content:
                hashes[alg] = content

        homepage, repository_url, download_url = self._extract_cyclonedx_external_refs(
            comp.get("externalReferences", [])
        )

        determined_source_type = self._determine_component_source(
            purl=purl,
            pkg_type=component_type,
            layer_digest=layer_digest,
            global_source_type=global_source_type,
        )

        # Inventory presents `type` as the ecosystem, so emit the purl vocabulary;
        # a fabricated purl only says "generic", so real generator hints win there.
        source_purl_type = get_purl_type(purl) if comp.get("purl") else None
        dep_type = source_purl_type or properties.get("syft:package:type") or get_purl_type(purl) or component_type

        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=dep_type,
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
        value: str, current_url: str | None, fallback_url: str | None = None
    ) -> tuple[str | None, str | None]:
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
        self, lic: dict[str, Any], license_names: list[str], license_url: str | None
    ) -> str | None:
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

    def _extract_cyclonedx_licenses_full(self, licenses: list[Any]) -> tuple[str, str | None]:
        """Extract license string and URL from CycloneDX license array."""
        if not licenses:
            return "", None

        license_names: list[str] = []
        license_url: str | None = None

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

    _SYFT_KNOWN_SOURCE_TYPES = (
        SOURCE_TYPE_IMAGE,
        SOURCE_TYPE_DIRECTORY,
        SOURCE_TYPE_FILE,
        SOURCE_TYPE_FILE_SYSTEM,
    )

    @classmethod
    def _resolve_syft_source(cls, source: dict[str, Any]) -> tuple[str | None, str | None]:
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
    def _build_syft_dependency_graph(
        relationships: list[dict[str, Any]], source_id: str
    ) -> tuple[set, set, dict[str, list], dict[str, list]]:
        """Return (confirmed_direct_ids, transitive_ids, forward_deps, parents_by_id).

        In syft's model `dependency-of` means 'parent IS A DEPENDENCY OF child',
        so the dependent is the child. `contains` only conveys containment, never
        directness; between artifacts it still yields a parent edge.
        """
        confirmed_direct: set = set()
        forward_deps: dict[str, list] = {}
        parents_by_id: dict[str, list] = {}

        for rel in relationships:
            if not isinstance(rel, dict):
                continue
            parent = rel.get("parent", "")
            child = rel.get("child", "")
            rel_type = rel.get("type", "")
            if not parent or not child:
                continue

            if rel_type == "depends-on":
                dependent, dependency = parent, child
            elif rel_type == "dependency-of":
                dependent, dependency = child, parent
            elif rel_type == "contains" and parent != source_id:
                parents_by_id.setdefault(child, []).append(parent)
                continue
            else:
                continue

            if dependent == source_id:
                confirmed_direct.add(dependency)
            else:
                forward_deps.setdefault(dependent, []).append(dependency)
                parents_by_id.setdefault(dependency, []).append(dependent)

        transitive_ids = {dep_id for children in forward_deps.values() for dep_id in children}
        return confirmed_direct, transitive_ids, forward_deps, parents_by_id

    @staticmethod
    def _syft_fallback_direct_ids(forward_deps: dict[str, list], transitive_ids: set) -> set:
        """When the source declares no dependencies, a single graph root is the scanned project; its children are the direct set."""
        roots = [dep_id for dep_id in forward_deps if dep_id not in transitive_ids]
        if len(roots) == 1:
            return set(forward_deps[roots[0]])
        return set()

    @staticmethod
    def _resolve_syft_directness(
        artifact_id: str,
        confirmed_direct: set,
        fallback_direct: set,
        transitive_ids: set,
    ) -> tuple[bool, bool]:
        if artifact_id in confirmed_direct:
            return True, False
        if artifact_id in fallback_direct:
            return True, True
        if artifact_id in transitive_ids:
            return False, False
        # The graph says nothing about this artifact (e.g. contains-only image
        # catalogs): keep it direct so inventory counts hold, but flag the guess.
        return True, True

    def _parse_syft(self, sbom: dict[str, Any], result: ParsedSBOM) -> None:
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

        artifacts = sbom.get("artifacts") or []
        relationships = sbom.get("artifactRelationships") or []
        self._count_skipped(result, "file", len(sbom.get("files") or []))

        confirmed_direct, transitive_ids, forward_deps, parents_by_id = self._build_syft_dependency_graph(
            relationships, source_id
        )
        fallback_direct: set = set()
        if not confirmed_direct:
            fallback_direct = self._syft_fallback_direct_ids(forward_deps, transitive_ids)

        logger.debug(
            f"Syft relationship analysis: {len(confirmed_direct)} confirmed direct, "
            f"{len(fallback_direct)} fallback direct, {len(transitive_ids)} transitive "
            f"from {len(relationships)} relationships"
        )

        parsed_by_id: dict[str, ParsedDependency] = {}
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                self._count_skipped(result, "malformed")
                continue
            artifact_id = artifact.get("id", "")
            is_direct, direct_inferred = self._resolve_syft_directness(
                artifact_id, confirmed_direct, fallback_direct, transitive_ids
            )

            try:
                parsed = self._parse_syft_artifact(
                    artifact,
                    result.source_type,
                    result.source_target,
                    is_direct,
                    direct_inferred,
                )
            except Exception:
                logger.warning("Skipping malformed Syft artifact %r", artifact.get("name"), exc_info=True)
                self._count_skipped(result, "parse-error")
                continue
            if parsed:
                result.dependencies.append(parsed)
                if artifact_id:
                    parsed_by_id[artifact_id] = parsed
            else:
                self._count_skipped(result, "unidentifiable")

        # Second pass: parent ids only resolve once every artifact is parsed, and
        # they must be stored as purl/name@version so tree nodes can match them.
        for artifact_id, parsed in parsed_by_id.items():
            refs: list[str] = []
            for parent_id in parents_by_id.get(artifact_id, []):
                parent = parsed_by_id.get(parent_id)
                if parent is None:
                    continue
                ref = parent.purl or f"{parent.name}@{parent.version}"
                if ref not in refs:
                    refs.append(ref)
            parsed.parent_components = refs

    @staticmethod
    def _extract_syft_locations(
        location_entries: list[dict[str, Any]],
    ) -> tuple[list[str], str | None]:
        """Return (locations, first_layer_digest) from a syft location list."""
        locations: list[str] = []
        layer_digest: str | None = None
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
    def _extract_syft_author(metadata: dict[str, Any]) -> str | None:
        """Extract author/maintainer string from syft metadata."""
        authors = metadata.get("authors")
        if authors:
            if isinstance(authors, list):
                return ", ".join(authors)
            return str(authors)
        return metadata.get("author") or metadata.get("maintainer")

    @staticmethod
    def _extract_syft_hashes(metadata: dict[str, Any]) -> dict[str, str]:
        """Extract hashes from syft metadata (direct fields + digests array)."""
        hashes: dict[str, str] = {}
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
    def _resolve_syft_direct(is_direct: bool, metadata: dict[str, Any]) -> bool:
        """Combine relationship-based and metadata-flag directness."""
        if is_direct:
            return True
        return bool(metadata and (metadata.get("directDependency") or metadata.get("direct")))

    def _parse_syft_artifact(
        self,
        artifact: dict[str, Any],
        source_type: str | None,
        source_target: str | None,
        is_direct: bool = False,
        direct_inferred: bool = False,
    ) -> ParsedDependency | None:
        """Parse a single Syft artifact with all available fields."""

        purl = artifact.get("purl")
        name = artifact.get("name")
        version = self._normalize_version(artifact.get("version"))
        pkg_type = artifact.get("type", "unknown")

        if not name:
            return None

        if not purl:
            if version == "unknown":
                # Neither a real identifier nor a comparable version.
                return None
            purl = self._construct_purl(pkg_type, name, version)
            logger.debug(f"Constructed PURL for Syft artifact {name}@{version}: {purl}")

        license_str, license_url = self._extract_syft_licenses_full(artifact.get("licenses") or [])
        locations, layer_digest = self._extract_syft_locations(artifact.get("locations") or [])
        # Syft JSON schema < 16.0 emits `cpes` as a list of plain strings; newer
        # releases use a list of dicts ({"cpe": "..."}). Handle both so a legacy
        # SBOM does not crash the artifact loop and silently drop dependencies.
        cpes = [(c.get("cpe") if isinstance(c, dict) else c) for c in artifact.get("cpes") or [] if c]
        cpes = [c for c in cpes if c]
        found_by = artifact.get("foundBy")

        metadata = artifact.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        direct = self._resolve_syft_direct(is_direct, metadata)
        description = metadata.get("description") or metadata.get("summary")
        author = self._extract_syft_author(metadata)
        homepage = metadata.get("homepage") or metadata.get("url")
        # deb/rpm metadata.source is the *source package name*, not a URL.
        repository_url = next(
            (v for v in (metadata.get("source"), metadata.get("repository")) if isinstance(v, str) and is_url(v)),
            None,
        )
        hashes = self._extract_syft_hashes(metadata)

        # Syft puts language on the artifact itself; metadata only backfills.
        properties = {}
        for key in ("language", "origin", "architecture", "filesAnalyzed"):
            value = artifact.get(key) or metadata.get(key)
            if value:
                properties[key] = str(value)

        # Determine component-specific source type
        determined_source_type = self._determine_component_source(
            purl=purl,
            pkg_type=pkg_type,
            layer_digest=layer_digest,
            global_source_type=source_type,
        )

        # Inventory presents `type` as the ecosystem: purl vocabulary when the
        # SBOM carried a purl, the raw syft artifact type otherwise.
        dep_type = (get_purl_type(purl) if artifact.get("purl") else None) or pkg_type

        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=dep_type,
            license=license_str,
            license_url=license_url,
            scope=None,
            direct=direct,
            direct_inferred=direct_inferred,
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
    def _syft_license_dict_url(lic: dict[str, Any]) -> str | None:
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
        self, lic: dict[str, Any], license_names: list[str], license_url: str | None
    ) -> str | None:
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

    def _extract_syft_licenses_full(self, licenses: list[Any]) -> tuple[str, str | None]:
        """Extract license string and URL from Syft license array."""
        if not licenses:
            return "", None

        license_names: list[str] = []
        license_url: str | None = None

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
        unique: list[str] = []
        for lic in license_names:
            if lic not in seen:
                seen.add(lic)
                unique.append(lic)

        return ", ".join(unique), license_url

    def _build_spdx_dependency_graph(
        self, relationships: list[dict[str, Any]], doc_spdx_id: str
    ) -> tuple[set, dict[str, list], set]:
        """
        Build SPDX dependency-graph data used to classify direct vs transitive deps.

        In the canonical SPDX layout (e.g. a GitHub SBOM export) the document
        DESCRIBES a root package (the application/repo); that root's DEPENDS_ON
        children are the DIRECT dependencies and the root package itself is NOT a
        dependency. Only when a DESCRIBES target has no DEPENDS_ON children (minimal
        SBOMs) is the described package itself the direct dep. Packages the document
        points at directly via CONTAINS/DEPENDS_ON are treated as direct.

        Returns:
            Tuple of (direct_package_ids, reverse_deps_graph, app_root_ids) where
            app_root_ids are DESCRIBES targets with DEPENDS_ON children — the scanned
            application itself, which must not be ingested as a dependency.
        """
        described_roots: set = set()  # application roots (DOCUMENT DESCRIBES ...)
        doc_direct_targets: set = set()  # packages the DOCUMENT points at directly
        forward_deps: dict[str, list] = {}  # element -> [children] via DEPENDS_ON
        all_dependency_targets: set = set()  # every DEPENDS_ON target (transitive candidates)
        packages_with_deps: set = set()  # elements that declare DEPENDS_ON edges
        reverse_deps_graph: dict[str, list] = {}

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

        app_root_ids = {root for root in described_roots if forward_deps.get(root)}
        return direct_package_ids, reverse_deps_graph, app_root_ids

    def _parse_spdx(self, sbom: dict[str, Any], result: ParsedSBOM) -> None:
        """Parse SPDX format SBOM."""

        result.tool_name = "spdx"
        result.format_version = sbom.get("spdxVersion")
        result.created_at = sbom.get("creationInfo", {}).get("created")

        relationships = sbom.get("relationships") or []
        doc_spdx_id = sbom.get("SPDXID", "SPDXRef-DOCUMENT")

        direct_package_ids, reverse_deps_graph, app_root_ids = self._build_spdx_dependency_graph(
            relationships, doc_spdx_id
        )

        packages = sbom.get("packages") or []
        inferred = not bool(relationships)
        self._count_skipped(result, "file", len(sbom.get("files") or []))

        root_pkg = next((p for p in packages if isinstance(p, dict) and p.get("SPDXID") in app_root_ids), None)
        if root_pkg is not None:
            result.source_type = SOURCE_TYPE_APPLICATION
            result.source_target = root_pkg.get("name")

        parsed_by_id: dict[str, ParsedDependency] = {}
        for pkg in packages:
            if not isinstance(pkg, dict):
                self._count_skipped(result, "malformed")
                continue
            pkg_spdx_id = pkg.get("SPDXID", "")
            if pkg_spdx_id in app_root_ids:
                self._count_skipped(result, "root-component")
                continue

            is_direct = inferred or pkg_spdx_id in direct_package_ids

            try:
                parsed = self._parse_spdx_package(pkg, is_direct, inferred, result.source_type, result.source_target)
            except Exception:
                logger.warning("Skipping malformed SPDX package %r", pkg.get("name"), exc_info=True)
                self._count_skipped(result, "parse-error")
                continue
            if parsed:
                result.dependencies.append(parsed)
                if pkg_spdx_id:
                    parsed_by_id[pkg_spdx_id] = parsed
            else:
                self._count_skipped(result, "unidentifiable")

        # SPDXRef parents only resolve after all packages parsed; store them as
        # purl/name@version so tree nodes can match them. Refs to the skipped
        # root drop out here, leaving direct dependencies parentless as expected.
        for pkg_spdx_id, parsed in parsed_by_id.items():
            refs: list[str] = []
            for parent_id in reverse_deps_graph.get(pkg_spdx_id, []):
                parent = parsed_by_id.get(parent_id)
                if parent is None:
                    continue
                ref = parent.purl or f"{parent.name}@{parent.version}"
                if ref not in refs:
                    refs.append(ref)
            parsed.parent_components = refs

    _SPDX_DOWNLOAD_LOC_TYPE_MAP = (
        (("npmjs.org", "registry.npmjs"), "npm"),
        (("pypi.org", "pypi.python.org"), "pypi"),
        (("maven", "mvnrepository"), "maven"),
        (("crates.io",), "cargo"),
        (("rubygems",), "gem"),
    )

    @staticmethod
    def _extract_spdx_external_refs(
        external_refs: list[dict[str, Any]],
    ) -> tuple[str | None, list[str]]:
        """Return (purl, cpes) from an SPDX externalRefs list."""
        purl: str | None = None
        cpes: list[str] = []
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

    _SPDX_LICENSE_PLACEHOLDERS = ("NOASSERTION", "NONE", "")

    @classmethod
    def _resolve_spdx_license(cls, pkg: dict[str, Any]) -> tuple[str, str | None]:
        """Extract (license_str, license_url) from SPDX licenseConcluded/Declared."""
        license_concluded = pkg.get("licenseConcluded", "")
        license_declared = pkg.get("licenseDeclared", "")
        license_str = license_concluded if license_concluded not in cls._SPDX_LICENSE_PLACEHOLDERS else license_declared
        if not license_str or license_str in cls._SPDX_LICENSE_PLACEHOLDERS:
            license_str = ""

        license_url: str | None = None
        if is_url(license_str):
            license_url = license_str
            extracted = extract_license_from_url(license_str)
            license_str = extracted if extracted else ""
        return license_str, license_url

    @staticmethod
    def _resolve_spdx_originator(
        pkg: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        """Extract (author, publisher) from SPDX originator/supplier fields."""
        author: str | None = None
        publisher: str | None = None

        originator = pkg.get("originator")
        if originator and originator != "NOASSERTION":
            if originator.startswith(SPDX_ORGANIZATION_PREFIX):
                publisher = originator.replace(SPDX_ORGANIZATION_PREFIX, "").strip()
            elif originator.startswith("Person:"):
                author = originator.replace("Person:", "").strip()
            else:
                author = originator

        supplier = pkg.get("supplier")
        if supplier and supplier != "NOASSERTION" and not publisher and supplier.startswith(SPDX_ORGANIZATION_PREFIX):
            publisher = supplier.replace(SPDX_ORGANIZATION_PREFIX, "").strip()
        return author, publisher

    @staticmethod
    def _build_spdx_properties(pkg: dict[str, Any]) -> dict[str, str]:
        """Build the SPDX-specific 'properties' dict."""
        properties: dict[str, str] = {}
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
    def _extract_spdx_hashes(pkg: dict[str, Any]) -> dict[str, str]:
        """Extract a hash map from an SPDX package's checksums array."""
        hashes: dict[str, str] = {}
        for checksum in pkg.get("checksums", []):
            alg = checksum.get("algorithm", "").lower()
            value = checksum.get("checksumValue", "")
            if alg and value:
                hashes[alg] = value
        return hashes

    def _parse_spdx_package(
        self,
        pkg: dict[str, Any],
        is_direct: bool = False,
        direct_inferred: bool = False,
        global_source_type: str | None = None,
        source_target: str | None = None,
    ) -> ParsedDependency | None:
        """Parse a single SPDX package with all available fields."""

        name = pkg.get("name")
        version = self._normalize_version(pkg.get("versionInfo"))

        if not name or name in ("NOASSERTION", "NONE"):
            return None

        purl, cpes = self._extract_spdx_external_refs(pkg.get("externalRefs") or [])

        if not purl:
            if version == "unknown":
                # Neither a real identifier nor a comparable version.
                return None
            inferred_type = self._infer_spdx_pkg_type_from_download(pkg.get("downloadLocation") or "")
            purl = self._construct_purl(inferred_type, name, version)
            logger.debug(f"Constructed PURL for SPDX package {name}@{version}: {purl}")

        license_str, license_url = self._resolve_spdx_license(pkg)
        pkg_type = get_purl_type(purl) or "unknown"
        hashes = self._extract_spdx_hashes(pkg)

        homepage = pkg.get("homepage")
        if homepage == "NOASSERTION":
            homepage = None

        download_url = pkg.get("downloadLocation")
        if download_url in ("NOASSERTION", "NONE"):
            download_url = None

        author, publisher = self._resolve_spdx_originator(pkg)
        properties = self._build_spdx_properties(pkg)

        parsed_purl = parse_purl(purl) if purl else None
        package_file_name = pkg.get("packageFileName")

        determined_source_type = self._determine_component_source(
            purl=purl,
            pkg_type=pkg_type,
            layer_digest=None,  # SPDX doesn't have layer info
            global_source_type=global_source_type,
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
            source_type=determined_source_type,
            source_target=source_target,
            layer_digest=None,
            found_by=None,
            locations=[package_file_name] if package_file_name else [],
            cpes=cpes,
            description=pkg.get("description") or pkg.get("summary"),
            author=author,
            publisher=publisher,
            group=parsed_purl.namespace if parsed_purl else None,
            homepage=homepage,
            repository_url=None,  # Not directly in SPDX package
            download_url=download_url,
            hashes=hashes,
            properties=properties,
        )


# Singleton instance for easy import
sbom_parser = SBOMParser()


def parse_sbom(sbom: dict[str, Any]) -> ParsedSBOM:
    """Convenience function to parse an SBOM."""
    return sbom_parser.parse(sbom)
