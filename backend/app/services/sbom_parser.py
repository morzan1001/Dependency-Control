"""Unified parsing of CycloneDX, SPDX, and Syft JSON SBOMs into a common representation."""

import base64
import contextlib
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlparse

from app.core.constants import (
    APP_PACKAGE_TYPES,
    NON_RUNTIME_SCOPES,
    OS_PACKAGE_TYPES,
    SOURCE_TYPE_APPLICATION,
    SOURCE_TYPE_DIRECTORY,
    SOURCE_TYPE_FILE,
    SOURCE_TYPE_IMAGE,
    SPDX_ORGANIZATION_PREFIX,
)
from app.schemas.sbom import UNKNOWN_VERSION, ParsedDependency, ParsedSBOM, SBOMFormat, has_known_version
from app.core.purl import dependency_node_key, get_purl_type, is_os_package_type, parse_purl
from app.services.analyzers.base import normalize_hash_algorithm
from app.services.analyzers.license_compliance.normalizer import extract_license_from_url
from app.services.cbom_parser import parse_crypto_components

logger = logging.getLogger(__name__)

# SBOMs are untrusted input; without a cap, hostile nesting raises RecursionError
# and the format handler degrades the whole SBOM to zero components.
MAX_COMPONENT_NESTING_DEPTH = 100

_MERGED_LIST_FIELDS = ("locations", "parent_components", "cpes")


def merge_duplicate_dependencies(dependencies: list[ParsedDependency]) -> tuple[list[ParsedDependency], int]:
    """Collapse (name, version, purl) duplicates so the unique DB index doesn't silently drop them.

    Applied across every SBOM of a payload, not just within one: the index is per scan.
    """
    by_key: dict[tuple[str, str, str | None], ParsedDependency] = {}
    # Built on a key's first merge and kept: rebuilding per duplicate is quadratic again.
    seen_by_key: dict[tuple[str, str, str | None], dict[str, set[str]]] = {}
    merged = 0
    for dep in dependencies:
        key = (dep.name, dep.version, dep.purl)
        kept = by_key.get(key)
        if kept is None:
            by_key[key] = dep
            continue
        seen = seen_by_key.get(key)
        if seen is None:
            seen = seen_by_key[key] = {attr: set(getattr(kept, attr)) for attr in _MERGED_LIST_FIELDS}
        for attr in _MERGED_LIST_FIELDS:
            kept_values, kept_seen = getattr(kept, attr), seen[attr]
            for value in getattr(dep, attr):
                if value not in kept_seen:
                    kept_seen.add(value)
                    kept_values.append(value)
        for alg, digest in dep.hashes.items():
            kept.hashes.setdefault(alg, digest)
        kept.layer_digest = kept.layer_digest or dep.layer_digest
        kept.found_by = kept.found_by or dep.found_by
        # Graph-confirmed directness beats guesses; direct anywhere in the SBOM wins.
        if kept.direct_inferred and not dep.direct_inferred:
            kept.direct, kept.direct_inferred = dep.direct, False
        elif kept.direct_inferred == dep.direct_inferred:
            kept.direct = kept.direct or dep.direct
        if (kept.scope or "").lower() in NON_RUNTIME_SCOPES and (dep.scope or "").lower() not in NON_RUNTIME_SCOPES:
            kept.scope = dep.scope
        merged += 1
    return list(by_key.values()), merged


def _graph_entries(value: Any, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(entry, dict) for entry in value):
        raise ValueError(f"{field} must be a list of objects")
    return value


def _resolve_directness(
    forward: dict[Any, list[Any]], anchors: set[Any], transparent: set[Any], project: set[Any]
) -> tuple[Callable[[Any], tuple[bool, bool]], set[Any]]:
    """(ref -> (direct, direct_inferred), root refs that are the scanned subject rather than a dependency)."""
    targets = {child for children in forward.values() for child in children}
    subjects = {ref for ref in anchors if forward.get(ref)}
    inferred = not subjects
    seeds: list[Any] = []
    if inferred:
        roots = [ref for ref, children in forward.items() if children and ref not in targets]
        subjects = {ref for ref in roots if ref in project}
        seeds = [ref for ref in roots if ref not in subjects]
    seeds += [child for ref in subjects for child in forward[ref]]
    direct: set[Any] = set()
    while seeds:
        ref = seeds.pop()
        if ref not in direct:
            direct.add(ref)
            # Aggregator and OS-descriptor nodes are no dependency layer of their own.
            if ref in transparent:
                seeds.extend(forward.get(ref, ()))
    resolved = dict.fromkeys(targets, (False, inferred))
    resolved.update(dict.fromkeys(direct, (True, inferred)))
    resolved.update(dict.fromkeys(anchors - subjects, (True, False)))
    return lambda ref: resolved.get(ref, (True, True)), subjects


def _resolve_parent_refs(parsed_by_ref: dict[Any, ParsedDependency], *edge_maps: dict[Any, list[Any]]) -> None:
    """Set each parsed dependency's parents as node keys; refs of skipped components drop out."""
    parents: dict[Any, dict[str, None]] = {}
    for edges in edge_maps:
        for parent_ref, child_refs in edges.items():
            parent = parsed_by_ref.get(parent_ref)
            if parent is None:
                continue
            key = dependency_node_key(parent.purl, parent.name, parent.version)
            for child_ref in child_refs:
                if child_ref in parsed_by_ref:
                    parents.setdefault(child_ref, {})[key] = None
    for ref, parsed in parsed_by_ref.items():
        parsed.parent_components = list(parents.get(ref, {}))


def _image_reference(name: Any, version: Any) -> str | None:
    # An OCI tag never contains ':', so a version that does is a digest.
    separator = "@" if ":" in str(version) else ":"
    return f"{name}{separator}{version}" if version else name


def _has_local_origin(metadata: Any) -> bool:
    """Whether a syft lock-file entry is the checked-out project itself rather than a fetched package."""
    if not isinstance(metadata, dict):
        return False
    return (
        (metadata.get("resolved") == "" and not metadata.get("integrity"))
        or (metadata.get("checksum") == "" and not metadata.get("source"))
        or metadata.get("index") == "."
        or ("pomProject" in metadata and not metadata.get("virtualPath"))
    )


# Syft's CycloneDX output keeps no lock-file origin, so a root's cataloger marks it as the project.
_SYFT_PROJECT_ROOT_PROPERTIES = (
    ("syft:package:metadataType", "javascript-npm-package-lock-entry"),
    ("syft:package:metadataType", "rust-cargo-lock-entry"),
    ("syft:package:metadataType", "python-uv-lock-entry"),
    ("syft:package:foundBy", "java-pom-cataloger"),
)
# Trivy lock-file types whose single root package is the project; a Cargo workspace omits its members, so cargo is ambiguous.
_TRIVY_ROOT_PACKAGE_TYPES = tuple(("aquasecurity:trivy:Type", kind) for kind in ("pom", "gomod", "gobinary"))


def is_url(value: str) -> bool:
    """Check if a string is a URL."""
    if not value:
        return False
    try:
        result = urlparse(value)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
        return False


def _hash_map(entries: Any, alg_key: str, value_key: str) -> dict[str, str]:
    """Algorithm -> digest from a list of hash entries; the first digest per algorithm wins."""
    hashes: dict[str, str] = {}
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        alg, value = entry.get(alg_key), entry.get(value_key)
        if isinstance(alg, str) and isinstance(value, str) and alg and value:
            hashes.setdefault(normalize_hash_algorithm(alg), value)
    return hashes


def _people_to_str(value: Any) -> str | None:
    """Join a people field given as a string, a contact object or a list of either."""
    entries = value if isinstance(value, list) else [value]
    names = [(entry.get("name") or entry.get("email")) if isinstance(entry, dict) else entry for entry in entries]
    return ", ".join(name for name in names if isinstance(name, str) and name) or None


def _normalize_cpes(*sources: Any) -> list[str]:
    """CPE strings from each list source, deduplicated in first-seen order."""
    # Syft JSON before schema 16 emits plain strings, newer releases {"cpe": ...} dicts.
    values = (
        entry.get("cpe") if isinstance(entry, dict) else entry
        for source in sources
        if isinstance(source, list)
        for entry in source
    )
    return list(dict.fromkeys(value for value in values if isinstance(value, str) and value))


def _group_for(declared: str | None, purl: str | None) -> str | None:
    """The declared group, else the purl namespace where it is part of the package's name."""
    if declared:
        return declared
    parsed = parse_purl(purl) if purl else None
    # A golang namespace is the module host and a distro package's the vendor, not part of the name.
    if parsed is None or parsed.type == "golang" or parsed.type in OS_PACKAGE_TYPES:
        return None
    return parsed.namespace


_FABRICATED_PURL_TYPES = {"library": "generic", "framework": "generic", "container": "oci"}


def _purl_less_identity(
    kind: str, name: str, version: str, pkg_type: str, group: str | None, cpes: list[str]
) -> tuple[bool, str | None]:
    """(keep, purl) for a component without a purl; kind is 'os', 'binary' or 'package'."""
    if kind == "os":
        return True, None
    if kind == "binary":
        # A fabricated id for a binary-classifier hit matches no feed; only a CPE identifies it.
        return bool(cpes), None
    if not has_known_version(version):
        return False, None
    purl_type = _FABRICATED_PURL_TYPES.get(pkg_type, pkg_type)
    namespace = f"{quote(str(group), safe='')}/" if group else ""
    return True, f"pkg:{purl_type}/{namespace}{quote(str(name), safe='')}@{quote(str(version), safe='')}"


_SYFT_TYPE_TO_PURL_TYPE = {
    "binary": "generic",
    "dart-pub": "pub",
    "dotnet": "nuget",
    "erlang-otp": "otp",
    "github-action": "github",
    "go-module": "golang",
    "java-archive": "maven",
    "jenkins-plugin": "maven",
    "lua-rocks": "luarocks",
    "php-composer": "composer",
    "php-pear": "pear",
    "php-pecl": "pecl",
    "portage": "ebuild",
    "python": "pypi",
    "R-package": "cran",
    "rust-crate": "cargo",
}

_SYFT_SOURCE_TYPES = (SOURCE_TYPE_IMAGE, SOURCE_TYPE_DIRECTORY, SOURCE_TYPE_FILE)

_SPDX_NO_VALUE = frozenset({"NOASSERTION", "NONE", ""})


def _spdx_value(pkg: dict[str, Any], key: str) -> str | None:
    value = pkg.get(key)
    return value if isinstance(value, str) and value not in _SPDX_NO_VALUE else None


# osv derives a distro binary's source package from these; nothing reads any other raw property.
_OS_SOURCE_PACKAGE_PROPERTIES = tuple(
    f"aquasecurity:trivy:{key}" for key in ("SrcName", "SrcVersion", "SrcRelease", "SrcEpoch")
)


class SBOMParser:
    """Universal SBOM parser that handles multiple formats and normalizes output."""

    def __init__(self) -> None:
        self.format_handlers = {
            SBOMFormat.CYCLONEDX: self._parse_cyclonedx,
            SBOMFormat.SPDX: self._parse_spdx,
            SBOMFormat.SYFT: self._parse_syft,
        }

    @staticmethod
    def _detect_cyclonedx(sbom: dict[str, Any]) -> SBOMFormat | None:
        if sbom.get("bomFormat") == "CycloneDX" or "cyclonedx" in sbom.get("$schema", "").lower():
            return SBOMFormat.CYCLONEDX
        components = sbom.get("components")
        if isinstance(components, list) and components and isinstance(components[0], dict) and "purl" in components[0]:
            return SBOMFormat.CYCLONEDX
        return None

    @staticmethod
    def _detect_spdx(sbom: dict[str, Any]) -> SBOMFormat | None:
        if sbom.get("spdxVersion") or "SPDX" in sbom.get("$schema", ""):
            return SBOMFormat.SPDX
        return None

    @staticmethod
    def _detect_syft(sbom: dict[str, Any]) -> SBOMFormat | None:
        if isinstance(sbom.get("artifacts"), list) and (
            sbom.get("descriptor", {}).get("name") == "syft" or "source" in sbom
        ):
            return SBOMFormat.SYFT
        source = sbom.get("source")
        if isinstance(source, dict) and source.get("type") in _SYFT_SOURCE_TYPES:
            return SBOMFormat.SYFT
        return None

    def detect_format(self, sbom: dict[str, Any]) -> SBOMFormat:
        return self._detect_cyclonedx(sbom) or self._detect_spdx(sbom) or self._detect_syft(sbom) or SBOMFormat.UNKNOWN

    def parse(self, sbom: dict[str, Any]) -> ParsedSBOM:
        """Parse an SBOM and return normalized representation."""

        format_type = self.detect_format(sbom)

        result = ParsedSBOM(format=format_type)

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
                candidate = ParsedSBOM(format=format_type)
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

        result.dependencies, merged = merge_duplicate_dependencies(result.dependencies)
        result.merged_components += merged

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
    def _normalize_version(cls, raw: Any, purl: str | None = None) -> str:
        """The version, else the purl's version, else UNKNOWN_VERSION."""
        version = str(raw).strip() if isinstance(raw, (str, int, float)) else ""
        if version.lower() not in cls._PLACEHOLDER_VERSIONS:
            return version
        parsed = parse_purl(purl) if purl else None
        return cls._normalize_version(parsed.version) if parsed else UNKNOWN_VERSION

    @staticmethod
    def _build_cyclonedx_deps_graph(dependencies: Any) -> dict[Any, list[Any]]:
        forward: dict[Any, list[Any]] = {}
        for entry in _graph_entries(dependencies, "dependencies"):
            ref, depends_on = entry.get("ref"), entry.get("dependsOn") or []
            if not isinstance(depends_on, list) or not all(isinstance(r, str) for r in (ref, *depends_on)):
                raise ValueError("dependencies entries need a string ref and a string list dependsOn")
            forward.setdefault(ref, []).extend(depends_on)
        return forward

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
    _NON_PACKAGE_COMPONENT_TYPES = _NON_DEPENDENCY_COMPONENT_TYPES | {"file", "cryptographic-asset", "operating-system"}

    @classmethod
    def _cyclonedx_graph_roles(
        cls, components: list[dict[str, Any]], forward: dict[Any, list[Any]]
    ) -> tuple[set[Any], set[Any], set[Any]]:
        """(graph refs that are no package, Trivy lock-file root packages, syft roots that are the scanned project)."""
        packages: set[str] = set()
        trivy_roots: set[Any] = set()
        syft_roots_by_lock: dict[str, list[str]] = {}
        targets = set().union(*forward.values())
        for comp in components:
            ref, comp_type = comp.get("bom-ref") or comp.get("purl"), comp.get("type")
            if not isinstance(ref, str) or comp_type in cls._NON_PACKAGE_COMPONENT_TYPES:
                continue
            props = [(p.get("name"), p.get("value")) for p in comp.get("properties") or [] if isinstance(p, dict)]
            # Trivy groups each lock file's packages under a purl-less application node.
            if comp_type == "application" and not comp.get("purl"):
                children = forward.get(ref, [])
                # A Go binary without a main module has no root package: its packages hang directly under the node.
                if (
                    len(children) == 1
                    and forward.get(children[0])
                    and any(prop in _TRIVY_ROOT_PACKAGE_TYPES for prop in props)
                ):
                    trivy_roots.add(children[0])
                continue
            packages.add(ref)
            if forward.get(ref) and ref not in targets and any(prop in _SYFT_PROJECT_ROOT_PROPERTIES for prop in props):
                lock = next((value for name, value in props if name == "syft:location:0:path"), None)
                syft_roots_by_lock.setdefault(str(lock), []).append(ref)
        # A second root in one lock file (an unlinked npm peer, a uv dev group) leaves the project ambiguous.
        project = {roots[0] for roots in syft_roots_by_lock.values() if len(roots) == 1}
        return set(forward).union(targets) - packages, trivy_roots, project

    def _parse_cyclonedx(self, sbom: dict[str, Any], result: ParsedSBOM) -> None:
        metadata = sbom.get("metadata", {})
        main_component = metadata.get("component")
        if not isinstance(main_component, dict):
            main_component = {}
        main_refs = {
            ref for ref in (main_component.get("bom-ref"), main_component.get("purl")) if isinstance(ref, str) and ref
        }
        result.source_type, result.source_target = self._extract_cyclonedx_source(
            main_component, metadata.get("properties") or []
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

        forward = self._build_cyclonedx_deps_graph(sbom.get("dependencies") or [])
        transparent, trivy_roots, project = self._cyclonedx_graph_roles(components, forward)
        directness, subjects = _resolve_directness(forward, main_refs, transparent | trivy_roots, project)
        # A tuple compares by equality, so an unhashable bom-ref cannot fail the whole document.
        root_refs = (*main_refs, *trivy_roots, *subjects)

        parsed_by_ref: dict[Any, ParsedDependency] = {}
        for comp in components:
            comp_type = comp.get("type")
            if comp_type in ("cryptographic-asset", "file"):
                # Crypto assets are parsed into crypto_assets; file-catalog entries aren't dependencies.
                self._count_skipped(result, comp_type)
            elif comp_type in self._NON_DEPENDENCY_COMPONENT_TYPES:
                self._count_skipped(result, "non-dependency")
            elif comp.get("bom-ref") in root_refs or comp.get("purl") in root_refs:
                self._count_skipped(result, "root-component")
            elif parsed := self._append_parsed(
                result,
                "CycloneDX component",
                self._parse_cyclonedx_component,
                comp,
                result.source_type,
                result.source_target,
                directness,
            ):
                parsed_by_ref[comp.get("bom-ref") or parsed.purl] = parsed
        _resolve_parent_refs(parsed_by_ref, forward)

    def _append_parsed(
        self,
        result: ParsedSBOM,
        label: str,
        parse_one: Callable[..., ParsedDependency | None],
        item: dict[str, Any],
        *args: Any,
    ) -> ParsedDependency | None:
        try:
            parsed = parse_one(item, *args)
        except Exception:
            logger.warning("Skipping malformed %s %r", label, item.get("name"), exc_info=True)
            self._count_skipped(result, "parse-error")
            return None
        if parsed is None:
            self._count_skipped(result, "unidentifiable")
        else:
            result.dependencies.append(parsed)
        return parsed

    @staticmethod
    def _extract_cyclonedx_source(component: dict[str, Any], properties: Any) -> tuple[str | None, str | None]:
        source_type = None
        source_target = None
        comp_type = component.get("type")
        comp_name = component.get("name")
        if comp_type == "container":
            source_type = SOURCE_TYPE_IMAGE
            source_target = _image_reference(comp_name, component.get("version"))
        elif comp_type in ("application", "library"):
            source_type = SOURCE_TYPE_APPLICATION
            source_target = comp_name
        elif comp_type == "file":
            source_type = SOURCE_TYPE_FILE
            source_target = comp_name

        for prop in properties:
            if not isinstance(prop, dict):
                continue
            name = prop.get("name", "")
            if name == "aquasecurity:trivy:ImageName":
                source_type = SOURCE_TYPE_IMAGE
                source_target = prop.get("value", "")
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
        if is_os_package_type(purl, pkg_type) and (layer_digest or global_source_type == SOURCE_TYPE_IMAGE):
            return SOURCE_TYPE_IMAGE

        if (get_purl_type(purl) or pkg_type or "").lower() in APP_PACKAGE_TYPES:
            return SOURCE_TYPE_APPLICATION

        if layer_digest:
            return SOURCE_TYPE_IMAGE

        return global_source_type

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
            if field == "path" and prop_value:
                return None, None, prop_value
            # Anything else (accessPath, annotations:evidence etc.) is no canonical path.
            return None, None, None
        lower = prop_name.lower()
        if ("location" in lower or "path" in lower) and prop_value and not prop_name.startswith("syft:"):
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
            if prop_name in cls._CPE_PROPS and prop_value:
                cpes.append(prop_value)
                continue

            new_layer, new_found_by, new_location = cls._classify_cyclonedx_property(
                prop_name, prop_value, layer_digest
            )
            if new_layer is not None:
                layer_digest = new_layer
            if new_found_by is not None:
                found_by = new_found_by
            if new_location is not None:
                locations.append(new_location)

        evidence = comp.get("evidence")
        occurrences = evidence.get("occurrences") if isinstance(evidence, dict) else None
        for occ in occurrences if isinstance(occurrences, list) else []:
            loc = occ.get("location") if isinstance(occ, dict) else None
            if loc:
                locations.append(loc)

        return layer_digest, found_by, list(dict.fromkeys(locations)), properties, cpes

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
    ) -> tuple[str | None, str | None, str | None, list[Any]]:
        """Return (homepage, repository_url, download_url, distribution hash entries) from externalReferences."""
        homepage: str | None = None
        repository_url: str | None = None
        download_url: str | None = None
        distribution_hashes: list[Any] = []
        for ref in external_refs if isinstance(external_refs, list) else []:
            if not isinstance(ref, dict):
                continue
            ref_type = ref.get("type", "").lower()
            ref_url = ref.get("url", "")
            if ref_type == "website" and not homepage:
                homepage = ref_url
            elif ref_type in ("vcs", "git") and not repository_url:
                repository_url = cls._normalize_vcs_url(ref_url)
            elif ref_type in ("distribution", "download"):
                download_url = download_url or ref_url
                if isinstance(ref.get("hashes"), list):
                    distribution_hashes.extend(ref["hashes"])
        return homepage, repository_url, download_url, distribution_hashes

    def _parse_cyclonedx_component(
        self,
        comp: dict[str, Any],
        global_source_type: str | None,
        source_target: str | None,
        directness: Callable[[Any], tuple[bool, bool]],
    ) -> ParsedDependency | None:
        """Parse a single CycloneDX component with all available fields."""

        purl = comp.get("purl")
        name = comp.get("name")
        version = self._normalize_version(comp.get("version"), purl)
        bom_ref = comp.get("bom-ref")
        component_type = comp.get("type", "library")
        group = comp.get("group")

        if not name:
            return None
        # Every other producer names a scoped npm package "@scope/name"; the bare name is another package.
        if (
            isinstance(group, str)
            and group.startswith("@")
            and not name.startswith("@")
            and get_purl_type(purl) == "npm"
        ):
            name = f"{group}/{name}"

        layer_digest, found_by, locations, raw_properties, prop_cpes = self._extract_cyclonedx_properties(comp)
        # The spec field is the single string `cpe`; syft lists its CPEs as syft:cpe23 properties.
        cpes = _normalize_cpes([comp.get("cpe")], comp.get("cpes"), prop_cpes)
        syft_type = raw_properties.get("syft:package:type")
        pkg_type = _SYFT_TYPE_TO_PURL_TYPE.get(syft_type, syft_type) if syft_type else component_type

        if not purl:
            # OS descriptors stay without a purl: they feed base-image EOL detection.
            kind = {"operating-system": "os", "application": "binary"}.get(component_type, "package")
            keep, purl = _purl_less_identity(kind, name, version, pkg_type, group, cpes)
            if not keep:
                return None

        direct, direct_inferred = directness(bom_ref or purl)
        license_str, license_url = self._extract_cyclonedx_licenses_full(comp.get("licenses") or [])

        homepage, repository_url, download_url, distribution_hashes = self._extract_cyclonedx_external_refs(
            comp.get("externalReferences", [])
        )

        determined_source_type = self._determine_component_source(
            purl=purl,
            pkg_type=pkg_type,
            layer_digest=layer_digest,
            global_source_type=global_source_type,
        )

        scope = comp.get("scope")
        if not scope and raw_properties.get("cdx:npm:package:development") == "true":
            scope = "excluded"

        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            # Inventory presents `type` as the ecosystem, so emit the purl vocabulary.
            type=get_purl_type(purl) or pkg_type,
            license=license_str,
            license_url=license_url,
            scope=scope,
            direct=direct,
            direct_inferred=direct_inferred,
            source_type=determined_source_type,
            source_target=source_target,
            layer_digest=layer_digest,
            found_by=found_by,
            locations=locations,
            cpes=cpes,
            description=comp.get("description"),
            author=_people_to_str(comp.get("author") or comp.get("authors")),
            publisher=_people_to_str(comp.get("publisher") or comp.get("supplier")),
            group=_group_for(group, purl),
            homepage=homepage,
            repository_url=repository_url,
            download_url=download_url,
            hashes={
                **_hash_map(distribution_hashes, "alg", "content"),
                **_hash_map(comp.get("hashes"), "alg", "content"),
            },
            properties={key: raw_properties[key] for key in _OS_SOURCE_PACKAGE_PROPERTIES if key in raw_properties},
        )

    @staticmethod
    def _classify_license_value(
        value: str, current_url: str | None, fallback_url: str | None = None
    ) -> tuple[str | None, str | None]:
        """Classify a license value, returning (name_or_extracted, new_url_or_None)."""
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
                name_or_id = inner.get("id") or inner.get("name") or inner.get("url", "")
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

    @staticmethod
    def _resolve_syft_source(source: dict[str, Any]) -> tuple[str | None, str | None]:
        """Return (source_type, source_target) from a syft source of any JSON schema version."""
        source_type = source.get("type")
        if source_type not in _SYFT_SOURCE_TYPES:
            return None, None
        target = source.get("target")
        # Schema 5 keeps image details in a `target` object; newer schemas moved them to `metadata`.
        details = [d for d in (target, source.get("metadata")) if isinstance(d, dict)]
        candidates = (
            target,
            *(d.get(key) for d in details for key in ("userInput", "imageID", "path")),
            source.get("name"),
        )
        return source_type, next((c for c in candidates if isinstance(c, str) and c), None)

    @staticmethod
    def _build_syft_dependency_graph(
        relationships: Any, node_ids: set[Any]
    ) -> tuple[dict[Any, list[Any]], dict[Any, list[Any]]]:
        """(dependency, containment) edges between artifacts; 'dependency-of' reads 'parent IS A DEPENDENCY OF child'."""
        forward: dict[Any, list[Any]] = {}
        contains: dict[Any, list[Any]] = {}
        for rel in _graph_entries(relationships, "artifactRelationships"):
            parent, child, rel_type = rel.get("parent"), rel.get("child"), rel.get("type")
            if parent not in node_ids or child not in node_ids:
                continue
            if rel_type == "depends-on":
                forward.setdefault(parent, []).append(child)
            elif rel_type == "dependency-of":
                forward.setdefault(child, []).append(parent)
            elif rel_type == "contains":
                contains.setdefault(parent, []).append(child)
        return forward, contains

    def _parse_syft(self, sbom: dict[str, Any], result: ParsedSBOM) -> None:
        source = sbom.get("source", {})
        source_id = source.get("id", "")
        source_type, source_target = self._resolve_syft_source(source)
        if source_type is not None:
            result.source_type = source_type
            result.source_target = source_target

        raw_artifacts = sbom.get("artifacts") or []
        artifacts = [artifact for artifact in raw_artifacts if isinstance(artifact, dict)]
        self._count_skipped(result, "malformed", len(raw_artifacts) - len(artifacts))
        self._count_skipped(result, "file", len(sbom.get("files") or []))

        node_ids = {source_id, *(artifact.get("id") for artifact in artifacts)}
        forward, contains = self._build_syft_dependency_graph(sbom.get("artifactRelationships") or [], node_ids)
        project = {artifact.get("id") for artifact in artifacts if _has_local_origin(artifact.get("metadata"))}
        directness, subjects = _resolve_directness(forward, {source_id}, set(), project)

        parsed_by_id: dict[Any, ParsedDependency] = {}
        for artifact in artifacts:
            if artifact.get("id") in subjects:
                self._count_skipped(result, "root-component")
            elif parsed := self._append_parsed(
                result, "Syft artifact", self._parse_syft_artifact, artifact, source_type, source_target, directness
            ):
                parsed_by_id[artifact.get("id")] = parsed
        _resolve_parent_refs(parsed_by_id, forward, contains)

    @staticmethod
    def _extract_syft_locations(
        location_entries: list[dict[str, Any]],
    ) -> tuple[list[str], str | None]:
        """Return (locations, first_layer_digest) from a syft location list."""
        # `path` is the resolved file; `accessPath` may be a symlink to it.
        locations = list(dict.fromkeys(loc["path"] for loc in location_entries if loc.get("path")))
        layer_digest = next((loc["layerID"] for loc in location_entries if loc.get("layerID")), None)
        return locations, layer_digest

    @staticmethod
    def _extract_syft_hashes(pkg_type: str, metadata: dict[str, Any]) -> dict[str, str]:
        """Hashes from syft metadata: plain fields, SRI integrity strings, digests and Cargo.lock checksums."""
        entries: list[dict[str, Any]] = [
            {"algorithm": alg, "value": metadata.get(alg)} for alg in ("md5", "sha1", "sha256")
        ]
        resolution = metadata.get("resolution")
        sri_values = (
            metadata.get("integrity"),
            resolution.get("integrity") if isinstance(resolution, dict) else None,
            metadata.get("sha512"),
        )
        for token in " ".join(v for v in sri_values if isinstance(v, str)).split():
            alg, _, digest = token.partition("-")
            if alg in ("sha1", "sha256", "sha512"):
                with contextlib.suppress(ValueError):
                    entries.append({"algorithm": alg, "value": base64.b64decode(digest, validate=True).hex()})
        if pkg_type == "cargo":
            entries.append({"algorithm": "sha256", "value": metadata.get("checksum")})
        return {**_hash_map(entries, "algorithm", "value"), **_hash_map(metadata.get("digest"), "algorithm", "value")}

    def _parse_syft_artifact(
        self,
        artifact: dict[str, Any],
        source_type: str | None,
        source_target: str | None,
        directness: Callable[[Any], tuple[bool, bool]],
    ) -> ParsedDependency | None:
        """Parse a single Syft artifact with all available fields."""

        purl = artifact.get("purl")
        name = artifact.get("name")
        version = self._normalize_version(artifact.get("version"), purl)
        raw_type = artifact.get("type", "unknown")
        pkg_type = _SYFT_TYPE_TO_PURL_TYPE.get(raw_type, raw_type)

        if not name:
            return None

        cpes = _normalize_cpes(artifact.get("cpes"))
        if not purl:
            kind = "binary" if raw_type == "binary" else "package"
            keep, purl = _purl_less_identity(kind, name, version, pkg_type, None, cpes)
            if not keep:
                return None

        license_str, license_url = self._extract_syft_licenses_full(artifact.get("licenses") or [])
        locations, layer_digest = self._extract_syft_locations(artifact.get("locations") or [])

        metadata = artifact.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        # npm's `url` is package.json's repository; deb/rpm's `source` names the source package.
        repository_candidates = (
            metadata.get("repository"),
            metadata.get("source"),
            metadata.get("url") if pkg_type == "npm" else None,
        )
        repository_url = next(
            (url for url in (self._normalize_vcs_url(v) for v in repository_candidates if isinstance(v, str)) if url),
            None,
        )
        homepage = metadata.get("homepage") or (None if pkg_type == "npm" else metadata.get("url")) or None
        is_direct, direct_inferred = directness(artifact.get("id"))

        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            # Inventory presents `type` as the ecosystem, so emit the purl vocabulary.
            type=get_purl_type(purl) or pkg_type,
            license=license_str,
            license_url=license_url,
            direct=is_direct or bool(metadata.get("directDependency") or metadata.get("direct")),
            direct_inferred=direct_inferred,
            source_type=self._determine_component_source(
                purl=purl,
                pkg_type=pkg_type,
                layer_digest=layer_digest,
                global_source_type=source_type,
            ),
            source_target=source_target,
            layer_digest=layer_digest,
            found_by=artifact.get("foundBy"),
            locations=locations,
            cpes=cpes,
            description=metadata.get("description") or metadata.get("summary"),
            author=_people_to_str(metadata.get("authors") or metadata.get("author") or metadata.get("maintainer")),
            group=_group_for(None, purl),
            homepage=homepage,
            repository_url=repository_url,
            hashes=self._extract_syft_hashes(pkg_type, metadata),
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
        # Syft fills spdxExpression only when it resolved the value to an SPDX id.
        value = lic.get("spdxExpression") or lic.get("value") or lic.get("type", "")
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

    @staticmethod
    def _build_spdx_dependency_graph(relationships: Any, doc_spdx_id: Any) -> tuple[dict[Any, list[Any]], set[Any]]:
        """(DEPENDS_ON edges with DEPENDENCY_OF reversed into them, the packages the document describes)."""
        forward: dict[Any, list[Any]] = {}
        described: set[Any] = set()
        for rel in _graph_entries(relationships, "relationships"):
            rel_type = rel.get("relationshipType")
            element, related = rel.get("spdxElementId"), rel.get("relatedSpdxElement")
            if rel_type == "DEPENDS_ON":
                forward.setdefault(element, []).append(related)
            elif rel_type == "DEPENDENCY_OF":
                forward.setdefault(related, []).append(element)
            elif rel_type in ("DESCRIBES", "DOCUMENT_DESCRIBES") and element == doc_spdx_id:
                described.add(related)
        return forward, described

    def _parse_spdx(self, sbom: dict[str, Any], result: ParsedSBOM) -> None:
        creation_info = sbom.get("creationInfo")
        creators = creation_info.get("creators") if isinstance(creation_info, dict) else None
        # osv reads a set found_by as "syft catalogued this", which only the syft creator tool can vouch for.
        found_by = next(
            (
                creator.removeprefix("Tool: ")
                for creator in (creators if isinstance(creators, list) else [])
                if isinstance(creator, str) and creator.startswith("Tool: syft-")
            ),
            None,
        )

        doc_spdx_id = sbom.get("SPDXID", "SPDXRef-DOCUMENT")
        forward, described = self._build_spdx_dependency_graph(sbom.get("relationships") or [], doc_spdx_id)
        # SPDX 2.2 names the described packages in documentDescribes instead of DESCRIBES relationships.
        described.update(ref for ref in sbom.get("documentDescribes") or [] if isinstance(ref, str))
        directness, subjects = _resolve_directness(forward, {doc_spdx_id, *described}, set(), set())

        packages = sbom.get("packages") or []
        self._count_skipped(result, "file", len(sbom.get("files") or []))

        for pkg in packages:
            if not isinstance(pkg, dict) or pkg.get("SPDXID") not in described:
                continue
            if pkg.get("primaryPackagePurpose") == "CONTAINER":
                result.source_type = SOURCE_TYPE_IMAGE
                result.source_target = _image_reference(pkg.get("name"), _spdx_value(pkg, "versionInfo"))
                break
            if pkg.get("SPDXID") in subjects:
                result.source_type, result.source_target = SOURCE_TYPE_APPLICATION, pkg.get("name")
                break

        parsed_by_id: dict[Any, ParsedDependency] = {}
        for pkg in packages:
            if not isinstance(pkg, dict):
                self._count_skipped(result, "malformed")
            elif pkg.get("SPDXID") in subjects:
                self._count_skipped(result, "root-component")
            elif parsed := self._append_parsed(
                result,
                "SPDX package",
                self._parse_spdx_package,
                pkg,
                directness,
                result.source_type,
                result.source_target,
                found_by,
            ):
                parsed_by_id[pkg.get("SPDXID")] = parsed
        _resolve_parent_refs(parsed_by_id, forward)

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
            elif ref_type in ("cpe22Type", "cpe23Type"):
                cpes.append(locator)
        return purl, _normalize_cpes(cpes)

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

        originator = _spdx_value(pkg, "originator")
        if originator and originator.startswith(SPDX_ORGANIZATION_PREFIX):
            publisher = originator.removeprefix(SPDX_ORGANIZATION_PREFIX).strip()
        elif originator:
            author = originator.removeprefix("Person:").strip()

        supplier = _spdx_value(pkg, "supplier")
        if supplier and not publisher and supplier.startswith(SPDX_ORGANIZATION_PREFIX):
            publisher = supplier.removeprefix(SPDX_ORGANIZATION_PREFIX).strip()
        return author, publisher

    def _parse_spdx_package(
        self,
        pkg: dict[str, Any],
        directness: Callable[[Any], tuple[bool, bool]],
        global_source_type: str | None,
        source_target: str | None,
        found_by: str | None,
    ) -> ParsedDependency | None:
        """Parse a single SPDX package with all available fields."""

        name = _spdx_value(pkg, "name")
        if not name:
            return None

        purl, cpes = self._extract_spdx_external_refs(pkg.get("externalRefs") or [])
        version = self._normalize_version(pkg.get("versionInfo"), purl)
        download_url = _spdx_value(pkg, "downloadLocation")

        if not purl:
            kind = {"OPERATING-SYSTEM": "os", "APPLICATION": "binary"}.get(
                str(pkg.get("primaryPackagePurpose")), "package"
            )
            inferred_type = self._infer_spdx_pkg_type_from_download(download_url or "")
            keep, purl = _purl_less_identity(kind, name, version, inferred_type, None, cpes)
            if not keep:
                return None

        license_str, license_url = self._resolve_spdx_license(pkg)
        pkg_type = get_purl_type(purl) or "unknown"
        author, publisher = self._resolve_spdx_originator(pkg)
        package_file_name = pkg.get("packageFileName")
        is_direct, direct_inferred = directness(pkg.get("SPDXID"))

        return ParsedDependency(
            name=name,
            version=version,
            purl=purl,
            type=pkg_type,
            license=license_str,
            license_url=license_url,
            direct=is_direct,
            direct_inferred=direct_inferred,
            source_type=self._determine_component_source(
                purl=purl,
                pkg_type=pkg_type,
                layer_digest=None,
                global_source_type=global_source_type,
            ),
            source_target=source_target,
            found_by=found_by,
            locations=[package_file_name] if package_file_name else [],
            cpes=cpes,
            description=pkg.get("description") or pkg.get("summary"),
            author=author,
            publisher=publisher,
            group=_group_for(None, purl),
            homepage=_spdx_value(pkg, "homepage"),
            download_url=download_url,
            hashes=_hash_map(pkg.get("checksums"), "algorithm", "checksumValue"),
        )


# Singleton instance for easy import
sbom_parser = SBOMParser()


def parse_sbom(sbom: dict[str, Any]) -> ParsedSBOM:
    """Convenience function to parse an SBOM."""
    return sbom_parser.parse(sbom)
