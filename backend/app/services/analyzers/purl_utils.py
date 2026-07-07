"""PURL parsing. Format: pkg:type/namespace/name@version?qualifiers#subpath. See package-url/purl-spec."""

from typing import Dict, NamedTuple, Optional
from urllib.parse import unquote

# Maximum lengths for PURL components to prevent DoS via unbounded strings
MAX_PURL_LENGTH = 2048  # Total PURL length
MAX_NAME_LENGTH = 256  # Package name
MAX_VERSION_LENGTH = 128  # Version string
MAX_NAMESPACE_LENGTH = 256  # Namespace/scope


class ParsedPURL(NamedTuple):
    """Parsed PURL components."""

    type: str  # pypi, npm, maven, go, cargo, nuget, etc.
    namespace: Optional[str]  # org name for maven, scope for npm, etc.
    name: str  # package name
    version: Optional[str]  # version
    qualifiers: Dict[str, str]  # optional qualifiers
    subpath: Optional[str]  # optional subpath

    @property
    def full_name(self) -> str:
        """Get the full package name including namespace."""
        if self.namespace:
            return f"{self.namespace}/{self.name}"
        return self.name

    @property
    def registry_system(self) -> Optional[str]:
        """Get the registry system name for deps.dev API."""
        return PURL_TYPE_TO_SYSTEM.get(self.type)

    @property
    def deps_dev_name(self) -> str:
        """Get the package name formatted for deps.dev API."""
        if self.type == "maven" and self.namespace:
            return f"{self.namespace}:{self.name}"
        if self.type in ("golang", "go"):
            # Go module names already include the full path (e.g. github.com/cespare/xxhash/v2)
            return self.name
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


def parse_purl(purl: str) -> Optional[ParsedPURL]:
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
        if "@" in rest:
            rest, version = rest.rsplit("@", 1)
            version = unquote(version)

        if "/" not in rest:
            return None

        purl_type, rest = rest.split("/", 1)
        purl_type = purl_type.lower()

        namespace = None
        name = rest

        if "/" in rest:
            parts = rest.rsplit("/", 1)
            if len(parts) != 2:
                return None
            if purl_type in ("npm",) and rest.startswith("@"):
                split_parts = rest.split("/", 1)
                if len(split_parts) != 2:
                    return None
                namespace, name = split_parts
            elif purl_type in ("golang", "go"):
                namespace = rest.split("/")[0]
                name = rest
            else:
                namespace = parts[0]
                name = parts[1]

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


def get_purl_type(purl: str) -> Optional[str]:
    """Extract just the type from a PURL string."""
    if not purl or not purl.startswith("pkg:"):
        return None

    try:
        type_part = purl[4:].split("/")[0].lower()
        return type_part
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
