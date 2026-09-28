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

    @property
    def full_name(self) -> str:
        """Get the full package name including namespace."""
        if self.namespace:
            return f"{self.namespace}/{self.name}"
        return self.name

    @property
    def registry_system(self) -> str | None:
        """Ecosystem label of the purl type, whether or not deps.dev serves it."""
        return PURL_TYPE_TO_SYSTEM.get(self.type)

    @property
    def deps_dev_system(self) -> str | None:
        """The deps.dev system serving this package, or None where deps.dev has no data."""
        system = PURL_TYPE_TO_SYSTEM.get(self.type)
        return system if system in _DEPS_DEV_SYSTEMS else None

    @property
    def deps_dev_name(self) -> str:
        """Get the package name formatted for deps.dev API."""
        if self.type == "maven" and self.namespace:
            return f"{self.namespace}:{self.name}"
        if self.type == "pypi":
            # deps.dev serves PyPI packages under their PEP 503 normalized name.
            return pep503_normalize(self.name)
        if self.namespace:
            return f"{self.namespace}/{self.name}"
        return self.name


def pep503_normalize(name: str) -> str:
    """PyPI project name in PEP 503 normal form: separator runs become '-', lowercased."""
    return _PYPI_NORMALIZE_RE.sub("-", name).lower()


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
_DEPS_DEV_SYSTEMS = frozenset({"npm", "pypi", "maven", "go", "cargo", "nuget", "rubygems"})


def parse_purl(purl: str) -> ParsedPURL | None:
    """Parse a PURL string into its components, or None if it is not one."""
    if not purl or not purl.startswith("pkg:") or len(purl) > MAX_PURL_LENGTH:
        return None

    # The first '?' or '#' ends the coordinates, as in canonical_purl.
    rest, _, qualifier_str = purl[4:].split("#", 1)[0].partition("?")
    qualifiers: dict[str, str] = {}
    for pair in qualifier_str.split("&"):
        key, separator, value = pair.partition("=")
        if separator:
            qualifiers[unquote(key)] = unquote(value)

    version = None
    at = rest.rfind("@")
    # An '@' opening a path segment is an unencoded npm scope; a name is never empty.
    if at > 0 and rest[at - 1] != "/":
        rest, version = rest[:at], unquote(rest[at + 1 :])

    purl_type, slash, path = rest.partition("/")
    if not slash:
        return None
    namespace, _, name = path.rpartition("/")
    final_namespace = unquote(namespace) or None
    final_name = unquote(name)

    # Validate lengths after unquoting, since URL decoding can expand strings.
    if (
        len(final_name) > MAX_NAME_LENGTH
        or len(final_namespace or "") > MAX_NAMESPACE_LENGTH
        or len(version or "") > MAX_VERSION_LENGTH
    ):
        return None

    return ParsedPURL(
        type=purl_type.lower(),
        namespace=final_namespace,
        name=final_name,
        version=version,
        qualifiers=qualifiers,
    )


# Types whose namespace and name the purl spec declares case-insensitive.
_CASE_INSENSITIVE_TYPES = ("alpm", "apk", "bitbucket", "composer", "deb", "github", "hex", "oci", "pub", "pypi")
_IDENTITY_PATTERN = r"^pkg:([^/]+)/([^?#]*?)(?:(?<!/)@[^@?#]*)?(?:[?#].*)?$"


def package_identity(purl: str | None, name: str, component_type: str | None, group: str | None) -> tuple[str, str]:
    """Version-free package identity ``(type, namespace/name)`` under the purl spec's per-type rules.

    Without a parseable purl the row is keyed by its component type and lowercased ``group/name``.
    """
    parsed = parse_purl(purl) if purl else None
    if parsed is None:
        namespace = (group or "").strip()
        path = f"{namespace}/{name.strip()}" if namespace else name.strip()
        return component_type or "", path.lower()
    path = parsed.full_name
    if parsed.type in _CASE_INSENSITIVE_TYPES:
        path = path.lower()
    if parsed.type == "pypi":
        path = pep503_normalize(path)
    return parsed.type, path


def _pep503_expr(name: dict[str, Any]) -> dict[str, Any]:
    """:func:`pep503_normalize` of a lowercased name as an aggregation expression."""
    dashed: dict[str, Any] = {"$replaceAll": {"input": name, "find": "_", "replacement": "-"}}
    dashed = {"$replaceAll": {"input": dashed, "find": ".", "replacement": "-"}}
    # Mongo has no regex replace; each pass halves a separator run, and parse_purl caps a path segment's length.
    for _ in range(max(MAX_NAME_LENGTH, MAX_NAMESPACE_LENGTH).bit_length()):
        dashed = {"$replaceAll": {"input": dashed, "find": "--", "replacement": "-"}}
    return dashed


def package_identity_expr() -> dict[str, Any]:
    """:func:`package_identity` as an aggregation expression over a dependency row."""
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
                        "path": {
                            "$let": {
                                "vars": {
                                    "group": {"$trim": {"input": {"$ifNull": ["$group", ""]}}},
                                    "name": {"$trim": {"input": {"$ifNull": ["$name", ""]}}},
                                },
                                "in": {
                                    "$toLower": {
                                        "$cond": [
                                            {"$eq": ["$$group", ""]},
                                            "$$name",
                                            {"$concat": ["$$group", "/", "$$name"]},
                                        ]
                                    }
                                },
                            }
                        },
                    },
                    {
                        "$let": {
                            "vars": {"type": {"$toLower": {"$arrayElemAt": ["$$m.captures", 0]}}},
                            "in": {
                                "type": "$$type",
                                "path": {"$cond": [{"$eq": ["$$type", "pypi"]}, _pep503_expr(folded), folded]},
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
    return purl[4:].split("/")[0].lower()


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
