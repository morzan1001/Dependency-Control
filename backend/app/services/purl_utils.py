"""PURL parsing. Format: pkg:type/namespace/name@version?qualifiers#subpath. See package-url/purl-spec."""

import re
from typing import Any, NamedTuple
from urllib.parse import unquote

_PYPI_NORMALIZE_RE = re.compile(r"[-_.]+")

# Maximum lengths for PURL components to prevent DoS via unbounded strings
MAX_PURL_LENGTH = 2048  # Total PURL length
MAX_NAME_LENGTH = 256  # Package name
MAX_VERSION_LENGTH = 128  # Version string
MAX_NAMESPACE_LENGTH = 256  # Namespace/scope


class ParsedPURL(NamedTuple):
    """Parsed PURL components."""

    type: str  # pypi, npm, maven, go, cargo, nuget, etc.
    namespace: str | None  # org name for maven, scope for npm, etc.
    name: str  # package name
    version: str | None  # version
    qualifiers: dict[str, str]  # optional qualifiers
    subpath: str | None  # optional subpath

    @property
    def full_name(self) -> str:
        """Get the full package name including namespace."""
        if self.namespace:
            return f"{self.namespace}/{self.name}"
        return self.name

    @property
    def registry_system(self) -> str | None:
        """Get the registry system name for deps.dev API."""
        return PURL_TYPE_TO_SYSTEM.get(self.type)

    @property
    def deps_dev_name(self) -> str:
        """Get the package name formatted for deps.dev API."""
        if self.type == "maven" and self.namespace:
            return f"{self.namespace}:{self.name}"
        if self.type == "pypi":
            # deps.dev serves PyPI packages under their PEP 503 normalized name.
            return _PYPI_NORMALIZE_RE.sub("-", self.name).lower()
        if self.namespace:
            return f"{self.namespace}/{self.name}"
        return self.name


PURL_TYPE_TO_SYSTEM = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "golang": "go",
    "go": "go",
    "cargo": "cargo",
    "nuget": "nuget",
    "gem": "rubygems",
    "composer": "packagist",
    "cocoapods": "cocoapods",
    "swift": "swift",
    "pub": "pub",  # Dart
    "hex": "hex",  # Erlang/Elixir
    "cran": "cran",  # R
}


def parse_purl(purl: str) -> ParsedPURL | None:
    """Parse a PURL string into its components, or None if parsing fails."""
    if not purl or not purl.startswith("pkg:"):
        return None

    # Bound total length to prevent DoS.
    if len(purl) > MAX_PURL_LENGTH:
        return None

    try:
        rest = purl[4:]

        subpath = None
        if "#" in rest:
            rest, subpath = rest.rsplit("#", 1)
            subpath = unquote(subpath)

        qualifiers = {}
        if "?" in rest:
            rest, qualifier_str = rest.rsplit("?", 1)
            for pair in qualifier_str.split("&"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    qualifiers[unquote(key)] = unquote(value)

        version = None
        # Only an '@' after the last '/' starts the version; the one in '@scope' does not.
        if "@" in rest.rsplit("/", 1)[-1]:
            rest, version = rest.rsplit("@", 1)
            version = unquote(version)

        if "/" not in rest:
            return None

        purl_type, rest = rest.split("/", 1)
        purl_type = purl_type.lower()

        namespace, _, name = rest.rpartition("/")

        final_namespace = unquote(namespace) if namespace else None
        final_name = unquote(name)

        # Validate lengths after unquoting, since URL decoding can expand strings.
        if len(final_name) > MAX_NAME_LENGTH:
            return None
        if final_namespace and len(final_namespace) > MAX_NAMESPACE_LENGTH:
            return None
        if version and len(version) > MAX_VERSION_LENGTH:
            return None

        return ParsedPURL(
            type=purl_type,
            namespace=final_namespace,
            name=final_name,
            version=version,
            qualifiers=qualifiers,
            subpath=subpath,
        )

    except (ValueError, IndexError, AttributeError):
        return None


# Types whose namespace and name the purl spec declares case-insensitive.
_CASE_INSENSITIVE_TYPES = ("alpm", "apk", "bitbucket", "composer", "deb", "github", "hex", "oci", "pub", "pypi")
_IDENTITY_PATTERN = r"^pkg:([^/]+)/([^?#]*?)(?:@[^/?#]*)?(?:[?#].*)?$"


def package_identity(purl: str | None, name: str, component_type: str | None) -> tuple[str, str]:
    """Version-free package identity ``(type, namespace/name)`` under the purl spec's per-type rules.

    Without a parseable purl the row is keyed by its component type and lowercased name.
    """
    parsed = parse_purl(purl) if purl else None
    if parsed is None:
        return component_type or "", name.strip().lower()
    path = parsed.full_name
    if parsed.type in _CASE_INSENSITIVE_TYPES:
        path = path.lower()
    if parsed.type == "pypi":
        path = path.replace("_", "-")
    return parsed.type, path


def package_identity_expr() -> dict[str, Any]:
    """:func:`package_identity` as an aggregation expression over a dependency row's ``purl``, ``name`` and ``type``."""
    # Mongo cannot percent-decode; '%40' (the npm scope) is the only escape producers write in a package path.
    path = {"$replaceAll": {"input": {"$arrayElemAt": ["$$m.captures", 1]}, "find": "%40", "replacement": "@"}}
    folded = {"$cond": [{"$in": ["$$type", list(_CASE_INSENSITIVE_TYPES)]}, {"$toLower": path}, path]}
    return {
        "$let": {
            "vars": {"m": {"$regexFind": {"input": {"$ifNull": ["$purl", ""]}, "regex": _IDENTITY_PATTERN}}},
            "in": {
                "$cond": [
                    {"$eq": ["$$m", None]},
                    {
                        "type": {"$ifNull": ["$type", ""]},
                        "path": {"$toLower": {"$trim": {"input": {"$ifNull": ["$name", ""]}}}},
                    },
                    {
                        "$let": {
                            "vars": {"type": {"$toLower": {"$arrayElemAt": ["$$m.captures", 0]}}},
                            "in": {
                                "type": "$$type",
                                "path": {
                                    "$cond": [
                                        {"$eq": ["$$type", "pypi"]},
                                        {"$replaceAll": {"input": folded, "find": "_", "replacement": "-"}},
                                        folded,
                                    ]
                                },
                            },
                        }
                    },
                ]
            },
        }
    }


def dependency_node_key(purl: str | None, name: str, version: str) -> str:
    """Versioned node key of the dependency graph: what parent_components store and tree readers match."""
    return purl or f"{name}@{version}"


def canonical_purl(purl: str) -> str:
    """Cross-scan join key: qualifiers/subpath only describe packaging variants of the same artifact."""
    if not purl:
        return purl
    for separator in ("?", "#"):
        purl = purl.split(separator, 1)[0]
    return purl


def get_purl_type(purl: str | None) -> str | None:
    """Extract just the type from a PURL string."""
    if not purl or not purl.startswith("pkg:"):
        return None

    try:
        return purl[4:].split("/")[0].lower()
    except (IndexError, AttributeError):
        return None


def is_purl_type(purl: str, expected_type: str | tuple[str, ...]) -> bool:
    """Check if a PURL matches the expected type(s)."""
    purl_type = get_purl_type(purl)
    if isinstance(expected_type, tuple):
        return purl_type in expected_type
    return purl_type == expected_type


def is_pypi(purl: str) -> bool:
    return is_purl_type(purl, "pypi")


def is_npm(purl: str) -> bool:
    return is_purl_type(purl, "npm")


def is_maven(purl: str) -> bool:
    return is_purl_type(purl, "maven")


def is_go(purl: str) -> bool:
    return is_purl_type(purl, ("go", "golang"))


def is_cargo(purl: str) -> bool:
    return is_purl_type(purl, "cargo")


def is_nuget(purl: str) -> bool:
    return is_purl_type(purl, "nuget")


def normalize_hash_algorithm(alg: str) -> str:
    """Normalize a hash algorithm name (lowercase, no hyphens): "SHA-256" -> "sha256"."""
    if not alg:
        return ""
    return alg.lower().replace("-", "")
