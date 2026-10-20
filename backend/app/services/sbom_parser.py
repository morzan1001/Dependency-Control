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
    UNKNOWN_LICENSE_PATTERNS,
)
from app.schemas.sbom import UNKNOWN_VERSION, ParsedDependency, ParsedSBOM, SBOMFormat, has_known_version
from app.core.purl import dependency_node_key, get_purl_type, is_os_package_type, parse_purl
from app.services.analyzers.hash_verification import normalize_hash_algorithm
from app.services.analyzers.license_compliance.constants import LICENSE_DATABASE
from app.services.analyzers.license_compliance.normalizer import (
    BUNDLE_LICENSE_PARAMETER,
    extract_license_from_url,
    normalize_license,
    split_license_list,
    strip_license_parameters,
)
from app.services.cbom_parser import (
    MAX_COMPONENT_NESTING_DEPTH,
    flatten_cyclonedx_components,
    occurrence_locations,
    parse_crypto_components,
)

logger = logging.getLogger(__name__)

_MERGED_LIST_FIELDS = ("locations", "parent_components", "cpes")
_MERGED_SCALAR_FIELDS = (
    "license",
    "license_url",
    "description",
    "author",
    "publisher",
    "group",
    "homepage",
    "repository_url",
    "download_url",
    "layer_digest",
    "found_by",
)

_SPDX_OPERATORS = frozenset({"AND", "OR", "WITH"})
# Maven's POM model and npm's legacy licenses array list licences a consumer may choose between.
_LICENSE_CHOICE_PURL_TYPES = frozenset({"maven", "npm"})
_SPDX_LICENSE_REF = re.compile(r"LicenseRef-[A-Za-z0-9.\-]+")
_HEX_SHA512 = re.compile(r"[0-9a-fA-F]{128}")

SKIP_CRYPTO_ASSET = "cryptographic-asset"
_SKIP_FILE = "file"
_SKIP_NON_DEPENDENCY = "non-dependency"
_SKIP_ROOT = "root-component"
# Skips of entries that are no dependencies; every other skip reason counts a lost component.
DELIBERATE_SKIP_REASONS = frozenset({SKIP_CRYPTO_ASSET, _SKIP_FILE, _SKIP_NON_DEPENDENCY, _SKIP_ROOT})


def _join_licenses(entries: list[str], purl: str | None) -> str:
    unique = list(dict.fromkeys(entries))
    if len(unique) < 2:
        return "".join(unique)
    parsed = parse_purl(purl or "")
    operator = " OR " if parsed and parsed.type in _LICENSE_CHOICE_PURL_TYPES else " AND "
    return operator.join(f"({entry})" if _SPDX_OPERATORS.intersection(entry.split()) else entry for entry in unique)


def _license_entries(value: str) -> tuple[list[str], str | None]:
    """A Bundle-License header can list several licences, each with its parameters: "a";link="u1",b;link=u2."""
    if not BUNDLE_LICENSE_PARAMETER.search(value):
        return [value], None
    entries = [_classify_license_value(*strip_license_parameters(entry)) for entry in split_license_list(value)]
    return [name for name, _ in entries if name], next((url for _, url in entries if url), None)


def _classify_license_value(value: str, fallback_url: str | None = None) -> tuple[str | None, str | None]:
    # A header can name its licence by URL: "https://www.apache.org/licenses/LICENSE-2.0;description=Apache-2.0".
    if is_url(value) and not BUNDLE_LICENSE_PARAMETER.search(value):
        return extract_license_from_url(value), value
    return value, fallback_url


# Quoted text matches whole, so an operator inside a quoted name or description never splits a value.
_EXPRESSION_PIECE = re.compile(r'(?:"[^"]*"|\S|\s(?!(?:OR|AND)\s))+|\s(?:OR|AND)\s')


def strip_license_header(value: str, purl: str | None) -> tuple[str, str | None]:
    """A header can sit among the other licences of an expression: 'MIT OR "Apache-2.0";link="u"'."""
    pieces, url = _EXPRESSION_PIECE.findall(value), None
    for index, piece in enumerate(pieces):
        names, piece_url = _license_entries(piece)
        joined = _join_licenses(names, purl)
        # A header listing several licences is one term of the expression around it.
        pieces[index] = f"({joined})" if len(pieces) > 1 and len(set(names)) > 1 else joined
        url = url or piece_url
    return "".join(pieces), url


def merge_duplicate_dependencies(dependencies: list[ParsedDependency]) -> tuple[list[ParsedDependency], int]:
    """The unique per-scan index would silently drop duplicates, so this runs across every SBOM of a payload."""
    by_key: dict[tuple[str, str, str | None], ParsedDependency] = {}
    # Built on a key's first merge and kept: rebuilding it per duplicate is quadratic.
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
        for attr in _MERGED_SCALAR_FIELDS:
            if not getattr(kept, attr):
                setattr(kept, attr, getattr(dep, attr))
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
    if not isinstance(name, str):
        return None
    # An OCI tag never contains ':', so a version that does is a digest.
    separator = "@" if ":" in str(version) else ":"
    return f"{name}{separator}{version}" if version else name


def _has_local_origin(metadata: Any) -> bool:
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
_TRIVY_ROOT_PACKAGE_TYPES = tuple(
    ("aquasecurity:trivy:Type", kind) for kind in ("pom", "gomod", "gobinary", "rustbinary", "dotnet-core", "uv")
)


def is_url(value: str) -> bool:
    if not value:
        return False
    try:
        result = urlparse(value)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
        return False


def _hash_map(entries: Any, alg_key: str, value_key: str) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        alg, value = entry.get(alg_key), entry.get(value_key)
        if isinstance(alg, str) and isinstance(value, str) and alg and value:
            hashes.setdefault(normalize_hash_algorithm(alg), value)
    return hashes


def _people_to_str(value: Any) -> str | None:
    entries = value if isinstance(value, list) else [value]
    names = [(entry.get("name") or entry.get("email")) if isinstance(entry, dict) else entry for entry in entries]
    return ", ".join(name for name in names if isinstance(name, str) and name) or None


def _normalize_cpes(*sources: Any) -> list[str]:
    # Syft JSON before schema 16 emits plain strings, newer releases {"cpe": ...} dicts.
    values = (
        entry.get("cpe") if isinstance(entry, dict) else entry
        for source in sources
        if isinstance(source, list)
        for entry in source
    )
    return list(dict.fromkeys(value for value in values if isinstance(value, str) and value))


def _group_for(declared: str | None, purl: str | None) -> str | None:
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
        format_type = self.detect_format(sbom)

        result = ParsedSBOM(format=format_type)

        # A document-level failure must propagate, or persistence would replace the dependency set with nothing.
        if format_type == SBOMFormat.UNKNOWN:
            logger.warning("Unknown SBOM format, attempting best-effort parsing")
            # A fresh result per attempt, so a failed handler leaves no partial dependencies or counters behind.
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
        return result

    @staticmethod
    def _count_skipped(result: ParsedSBOM, reason: str, count: int = 1) -> None:
        if count <= 0:
            return
        result.skipped_components += count
        result.skipped_reasons[reason] = result.skipped_reasons.get(reason, 0) + count

    @staticmethod
    def _append_distro(result: ParsedSBOM, distro_id: Any, version: Any, description: Any = None) -> None:
        """Shaped like the CycloneDX row base-image end-of-life detection reads."""
        if not (isinstance(distro_id, str) and distro_id and isinstance(version, str) and version):
            return
        result.dependencies.append(
            ParsedDependency(
                name=distro_id,
                version=version,
                type="operating-system",
                direct=True,
                direct_inferred=True,
                source_type=result.source_type,
                source_target=result.source_target,
                description=description if isinstance(description, str) else None,
            )
        )

    _PLACEHOLDER_VERSIONS = frozenset({"", "unknown", "noassertion", "none"})

    @classmethod
    def _normalize_version(cls, raw: Any, purl: str | None = None) -> str:
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

    _NON_DEPENDENCY_COMPONENT_TYPES = frozenset({"device", "device-driver", "data", "firmware"})
    _NON_PACKAGE_COMPONENT_TYPES = _NON_DEPENDENCY_COMPONENT_TYPES | {"file", "cryptographic-asset", "operating-system"}

    @classmethod
    def _cyclonedx_graph_roles(
        cls, components: list[dict[str, Any]], forward: dict[Any, list[Any]]
    ) -> tuple[set[Any], set[Any], set[Any]]:
        packages: set[str] = set()
        trivy_roots: set[Any] = set()
        refs_by_purl: dict[str, list[str]] = {}
        syft_roots_by_lock: dict[str, list[str]] = {}
        targets = set().union(*forward.values())
        for comp in components:
            ref, comp_type = comp.get("bom-ref") or comp.get("purl"), comp.get("type")
            if not isinstance(ref, str) or comp_type in cls._NON_PACKAGE_COMPONENT_TYPES:
                continue
            if isinstance(purl := comp.get("purl"), str) and purl:
                refs_by_purl.setdefault(purl, []).append(ref)
            raw_props = comp.get("properties")
            entries = raw_props if isinstance(raw_props, list) else []
            props = [(p.get("name"), p.get("value")) for p in entries if isinstance(p, dict)]
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
        # A module of the project roots its own lock-file node, so its copies elsewhere are the project too.
        trivy_roots.update(*(refs for refs in refs_by_purl.values() if trivy_roots.intersection(refs)))
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
            main_component, metadata.get("properties")
        )

        # cyclonedx-npm/-maven nest sub-dependencies in components[].components[].
        components, depth_skipped, malformed = flatten_cyclonedx_components(sbom.get("components", []))
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
            comp_type, bom_ref = comp.get("type"), comp.get("bom-ref")
            if comp_type in (SKIP_CRYPTO_ASSET, _SKIP_FILE):
                # Crypto assets are parsed into crypto_assets; file-catalog entries aren't dependencies.
                self._count_skipped(result, comp_type)
            elif comp_type in self._NON_DEPENDENCY_COMPONENT_TYPES:
                self._count_skipped(result, _SKIP_NON_DEPENDENCY)
            elif bom_ref in root_refs or comp.get("purl") in root_refs:
                self._count_skipped(result, _SKIP_ROOT)
            elif parsed := self._append_parsed(
                result,
                "CycloneDX component",
                self._parse_cyclonedx_component,
                comp,
                result.source_type,
                result.source_target,
                directness,
                # Trivy's purl-less lock-file and binary nodes only group packages.
                structural=comp_type == "application" and isinstance(bom_ref, str) and bom_ref in transparent,
            ):
                parsed_by_ref[bom_ref or parsed.purl] = parsed
        _resolve_parent_refs(parsed_by_ref, forward)

    def _append_parsed(
        self,
        result: ParsedSBOM,
        label: str,
        parse_one: Callable[..., ParsedDependency | None],
        item: dict[str, Any],
        *args: Any,
        structural: bool = False,
    ) -> ParsedDependency | None:
        try:
            parsed = parse_one(item, *args)
        except Exception:
            # One traceback per document; the parse summary counts the rest.
            if "parse-error" not in result.skipped_reasons:
                logger.warning("Skipping malformed %s %r", label, item.get("name"), exc_info=True)
            self._count_skipped(result, "parse-error")
            return None
        if parsed is None:
            self._count_skipped(result, _SKIP_NON_DEPENDENCY if structural else "unidentifiable")
        else:
            result.dependencies.append(parsed)
        return parsed

    @staticmethod
    def _extract_cyclonedx_source(component: dict[str, Any], properties: Any) -> tuple[str | None, str | None]:
        source_type = None
        source_target = None
        comp_type = component.get("type")
        comp_name = name if isinstance(name := component.get("name"), str) else None
        if comp_type == "container":
            source_type = SOURCE_TYPE_IMAGE
            source_target = _image_reference(comp_name, component.get("version"))
        elif comp_type in ("application", "library"):
            source_type = SOURCE_TYPE_APPLICATION
            source_target = comp_name
        elif comp_type == "file":
            source_type = SOURCE_TYPE_FILE
            source_target = comp_name

        for prop in properties if isinstance(properties, list) else []:
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
    _SYFT_LOCATION_PROP_RE = re.compile(r"^syft:location:\d+:(\w+)$")
    _PATH_NAME = re.compile("location|path")

    @classmethod
    def _extract_cyclonedx_properties(
        cls,
        comp: dict[str, Any],
    ) -> tuple[str | None, str | None, list[str], dict[str, str], list[str]]:
        layer_digest: str | None = None
        found_by: str | None = None
        locations: list[str] = []
        properties: dict[str, str] = {}
        cpes: list[str] = []

        raw_props = comp.get("properties")
        for prop in raw_props if isinstance(raw_props, list) else []:
            if not isinstance(prop, dict):
                continue
            name, value = prop.get("name", ""), prop.get("value", "")
            if name and value:
                properties[name] = value
            # Repeated syft:cpe23 properties collapse in the dict above, so CPEs must be collected while iterating.
            if name in cls._CPE_PROPS and value:
                cpes.append(value)
                continue
            syft_location = cls._SYFT_LOCATION_PROP_RE.match(name)
            field = syft_location.group(1) if syft_location else None
            if value is None:
                continue
            if name in cls._LAYER_DIGEST_PROPS:
                layer_digest = value
            elif name == cls._LAYER_DIFFID_PROP or field == "layerID":
                layer_digest = layer_digest or value
            elif name == cls._FOUND_BY_PROP:
                found_by = value
            elif value and (field == "path" or (not name.startswith("syft:") and cls._PATH_NAME.search(name.lower()))):
                locations.append(value)

        locations.extend(occurrence_locations(comp))
        return layer_digest, found_by, list(dict.fromkeys(locations)), properties, cpes

    @staticmethod
    def _normalize_vcs_url(raw: str) -> str | None:
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
        external_refs: Any,
    ) -> tuple[str | None, str | None, str | None, list[Any]]:
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
        license_str, license_url = self._extract_licenses_full(
            comp.get("licenses") or [], self._handle_cyclonedx_license_dict, purl
        )

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

    def _extract_licenses_full(
        self,
        licenses: list[Any],
        handle_dict: Callable[[dict[str, Any]], tuple[str | None, str | None]],
        purl: str | None,
    ) -> tuple[str, str | None]:
        names: list[str] = []
        license_url: str | None = None
        for lic in licenses:
            if isinstance(lic, dict):
                name, url = handle_dict(lic)
            elif isinstance(lic, str):
                name, url = _classify_license_value(lic)
            else:
                continue
            if name:
                entries, parameter_url = _license_entries(name)
                names += entries
                url = url or parameter_url
            license_url = license_url or url
        return _join_licenses(names, purl), license_url

    def _handle_cyclonedx_license_dict(self, lic: dict[str, Any]) -> tuple[str | None, str | None]:
        if "license" in lic:
            inner = lic["license"]
            if not isinstance(inner, dict):
                return None, None
            return _classify_license_value(
                inner.get("id") or inner.get("name") or inner.get("url", ""), inner.get("url")
            )
        for key in ("expression", "id", "name"):
            if key in lic:
                return _classify_license_value(lic[key], lic.get("url") if key != "expression" else None)
        return None, None

    @staticmethod
    def _resolve_syft_source(source: dict[str, Any]) -> tuple[str | None, str | None]:
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
        """Syft's 'dependency-of' reads 'parent IS A DEPENDENCY OF child'."""
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
        self._count_skipped(result, _SKIP_FILE, len(sbom.get("files") or []))

        node_ids = {source_id, *(artifact.get("id") for artifact in artifacts)}
        forward, contains = self._build_syft_dependency_graph(sbom.get("artifactRelationships") or [], node_ids)
        project = {artifact.get("id") for artifact in artifacts if _has_local_origin(artifact.get("metadata"))}
        directness, subjects = _resolve_directness(forward, {source_id}, set(), project)

        parsed_by_id: dict[Any, ParsedDependency] = {}
        for artifact in artifacts:
            if artifact.get("id") in subjects:
                self._count_skipped(result, _SKIP_ROOT)
            elif parsed := self._append_parsed(
                result, "Syft artifact", self._parse_syft_artifact, artifact, source_type, source_target, directness
            ):
                parsed_by_id[artifact.get("id")] = parsed
        _resolve_parent_refs(parsed_by_id, forward, contains)

        distro = sbom.get("distro")
        if isinstance(distro, dict):
            self._append_distro(result, distro.get("id"), distro.get("versionID"), distro.get("prettyName"))

    @staticmethod
    def _extract_syft_locations(
        location_entries: list[dict[str, Any]],
    ) -> tuple[list[str], str | None]:
        # `path` is the resolved file; `accessPath` may be a symlink to it.
        locations = list(dict.fromkeys(loc["path"] for loc in location_entries if loc.get("path")))
        layer_digest = next((loc["layerID"] for loc in location_entries if loc.get("layerID")), None)
        return locations, layer_digest

    @staticmethod
    def _extract_syft_hashes(pkg_type: str, metadata: dict[str, Any]) -> dict[str, str]:
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
        sha512 = metadata.get("sha512")
        if isinstance(sha512, str) and _HEX_SHA512.fullmatch(sha512):
            entries.append({"algorithm": "sha512", "value": sha512})
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

        license_str, license_url = self._extract_licenses_full(
            artifact.get("licenses") or [], self._handle_syft_license_dict, purl
        )
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
            # Syft's CycloneDX and SPDX writers name an RPM's vendor as its publisher.
            publisher=_people_to_str(metadata.get("vendor")),
            group=_group_for(None, purl),
            homepage=homepage,
            repository_url=repository_url,
            hashes=self._extract_syft_hashes(pkg_type, metadata),
        )

    @staticmethod
    def _syft_license_dict_url(lic: dict[str, Any]) -> str | None:
        for url_key in ("url", "urls"):
            url_val = lic.get(url_key)
            if url_val:
                return str(url_val[0] if isinstance(url_val, list) else url_val)
        return None

    def _handle_syft_license_dict(self, lic: dict[str, Any]) -> tuple[str | None, str | None]:
        dedicated_url = self._syft_license_dict_url(lic)
        # Syft fills spdxExpression only when it resolved the value to an SPDX id.
        value = lic.get("spdxExpression") or lic.get("value") or dedicated_url or ""
        return _classify_license_value(value, dedicated_url)

    @staticmethod
    def _build_spdx_dependency_graph(
        relationships: Any, doc_spdx_id: Any
    ) -> tuple[dict[Any, list[Any]], set[Any], set[str]]:
        forward: dict[Any, list[Any]] = {}
        described: set[Any] = set()
        containers: set[str] = set()
        for rel in _graph_entries(relationships, "relationships"):
            rel_type = rel.get("relationshipType")
            element, related = rel.get("spdxElementId"), rel.get("relatedSpdxElement")
            if rel_type == "DEPENDS_ON":
                forward.setdefault(element, []).append(related)
            elif rel_type == "DEPENDENCY_OF":
                forward.setdefault(related, []).append(element)
            elif rel_type in ("DESCRIBES", "DOCUMENT_DESCRIBES") and element == doc_spdx_id:
                described.add(related)
            elif rel_type == "CONTAINS" and isinstance(element, str):
                containers.add(element)
        return forward, described, containers

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
        forward, described, containers = self._build_spdx_dependency_graph(sbom.get("relationships") or [], doc_spdx_id)
        # SPDX 2.2 names the described packages in documentDescribes instead of DESCRIBES relationships.
        described.update(ref for ref in sbom.get("documentDescribes") or [] if isinstance(ref, str))
        directness, subjects = _resolve_directness(forward, {doc_spdx_id, *described}, set(), set())

        packages = sbom.get("packages") or []
        license_refs = self._spdx_license_refs(sbom)
        self._count_skipped(result, _SKIP_FILE, len(sbom.get("files") or []))

        roots = set(subjects)
        for pkg in packages:
            if not isinstance(pkg, dict) or pkg.get("SPDXID") not in described:
                continue
            if pkg.get("primaryPackagePurpose") == "CONTAINER":
                result.source_type = SOURCE_TYPE_IMAGE
                result.source_target = _image_reference(_spdx_value(pkg, "name"), _spdx_value(pkg, "versionInfo"))
                roots.add(pkg["SPDXID"])
                break
            if pkg.get("SPDXID") in subjects:
                result.source_type, result.source_target = SOURCE_TYPE_APPLICATION, _spdx_value(pkg, "name")
                break

        parsed_by_id: dict[Any, ParsedDependency] = {}
        for pkg in packages:
            if not isinstance(pkg, dict):
                self._count_skipped(result, "malformed")
            elif pkg.get("SPDXID") in roots:
                self._count_skipped(result, _SKIP_ROOT)
            elif parsed := self._append_parsed(
                result,
                "SPDX package",
                self._parse_spdx_package,
                pkg,
                license_refs,
                directness,
                result.source_type,
                result.source_target,
                found_by,
                # Trivy's purl-less lock-file and binary nodes only group packages.
                structural=pkg.get("SPDXID") in described
                or (pkg.get("primaryPackagePurpose") == "APPLICATION" and pkg.get("SPDXID") in containers),
            ):
                parsed_by_id[pkg.get("SPDXID")] = parsed
        _resolve_parent_refs(parsed_by_id, forward)

        if not any(
            isinstance(pkg, dict) and pkg.get("primaryPackagePurpose") == "OPERATING-SYSTEM" for pkg in packages
        ):
            # Syft's SPDX names the distro only in the purl qualifiers of its packages.
            distro_purls = (parse_purl(dep.purl or "") for dep in result.dependencies if dep.type in OS_PACKAGE_TYPES)
            distro = next(
                (purl.qualifiers["distro"] for purl in distro_purls if purl and "distro" in purl.qualifiers), ""
            )
            distro_id, _, version = distro.rpartition("-")
            self._append_distro(result, distro_id, version)

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
        for needles, pkg_type in cls._SPDX_DOWNLOAD_LOC_TYPE_MAP:
            if any(n in download_loc for n in needles):
                return pkg_type
        return "generic"

    @staticmethod
    def _spdx_license_refs(sbom: dict[str, Any]) -> dict[str, str]:
        refs: dict[str, str] = {}
        for info in sbom.get("hasExtractedLicensingInfos") or []:
            if not isinstance(info, dict) or not isinstance(info.get("licenseId"), str):
                continue
            # Trivy names the licence in `name` with a sentence in extractedText; syft puts the name in extractedText.
            for candidate in (info.get("name"), info.get("extractedText")):
                # Kept whole: only the package purl decides how a header's licences join.
                if isinstance(candidate, str) and BUNDLE_LICENSE_PARAMETER.search(candidate):
                    refs[info["licenseId"]] = candidate
                    break
                spdx_id = normalize_license(candidate) if isinstance(candidate, str) else ""
                if spdx_id in LICENSE_DATABASE:
                    refs[info["licenseId"]] = spdx_id
                    break
        return refs

    @staticmethod
    def _resolve_spdx_license(
        pkg: dict[str, Any], license_refs: dict[str, str], purl: str | None
    ) -> tuple[str, str | None]:
        license_str = next(
            (
                value
                for value in (_spdx_value(pkg, "licenseConcluded"), _spdx_value(pkg, "licenseDeclared"))
                if value and value.upper() not in UNKNOWN_LICENSE_PATTERNS
            ),
            "",
        )
        if is_url(license_str):
            return extract_license_from_url(license_str) or "", license_str
        return strip_license_header(
            _SPDX_LICENSE_REF.sub(lambda ref: license_refs.get(ref.group(), ref.group()), license_str), purl
        )

    @staticmethod
    def _resolve_spdx_originator(
        pkg: dict[str, Any],
    ) -> tuple[str | None, str | None]:
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
        license_refs: dict[str, str],
        directness: Callable[[Any], tuple[bool, bool]],
        global_source_type: str | None,
        source_target: str | None,
        found_by: str | None,
    ) -> ParsedDependency | None:
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

        license_str, license_url = self._resolve_spdx_license(pkg, license_refs, purl)
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


sbom_parser = SBOMParser()


def parse_sbom(sbom: dict[str, Any]) -> ParsedSBOM:
    return sbom_parser.parse(sbom)
