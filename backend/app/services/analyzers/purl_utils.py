"""
PURL (Package URL) Utilities

Provides centralized parsing and handling of Package URLs (PURLs).
See: https://github.com/package-url/purl-spec

Format: pkg:type/namespace/name@version?qualifiers#subpath
"""

import re
from typing import Any, Dict, NamedTuple, Optional
from urllib.parse import unquote


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


# Mapping from PURL types to deps.dev/registry system names
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

# Mapping for ecosystem names used in various APIs
PURL_TYPE_TO_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "go": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "gem": "RubyGems",
    "composer": "Packagist",
    "cocoapods": "CocoaPods",
    "swift": "SwiftPM",
    "pub": "Pub",
    "hex": "Hex",
    "cran": "CRAN",
}


def parse_purl(purl: str) -> Optional[ParsedPURL]:
    """
    Parse a PURL string into its components.

    Args:
        purl: Package URL string (e.g., "pkg:pypi/requests@2.31.0")

    Returns:
        ParsedPURL namedtuple or None if parsing fails
    """
    if not purl or not purl.startswith("pkg:"):
        return None

    try:
        # Remove "pkg:" prefix
        rest = purl[4:]

        # Extract subpath (after #)
        subpath = None
        if "#" in rest:
            rest, subpath = rest.rsplit("#", 1)
            subpath = unquote(subpath)

        # Extract qualifiers (after ?)
        qualifiers = {}
        if "?" in rest:
            rest, qualifier_str = rest.rsplit("?", 1)
            for pair in qualifier_str.split("&"):
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    qualifiers[unquote(key)] = unquote(value)

        # Extract version (after @)
        version = None
        if "@" in rest:
            rest, version = rest.rsplit("@", 1)
            version = unquote(version)

        # Extract type (before first /)
        if "/" not in rest:
            return None

        purl_type, rest = rest.split("/", 1)
        purl_type = purl_type.lower()

        # Extract namespace and name
        namespace = None
        name = rest

        # Handle namespaced packages
        if "/" in rest:
            # Maven: group/artifact
            # npm: @scope/name
            # Go: domain/path/name
            parts = rest.rsplit("/", 1)
            if purl_type == "maven":
                namespace = parts[0]
                name = parts[1]
            elif purl_type in ("npm",) and rest.startswith("@"):
                # npm scoped package: @scope/name
                namespace, name = rest.split("/", 1)
            elif purl_type in ("golang", "go"):
                # Go: keep full path as name, extract domain as namespace
                namespace = rest.split("/")[0]
                name = rest
            else:
                # For other types, treat as namespace/name
                namespace = parts[0]
                name = parts[1]

        return ParsedPURL(
            type=purl_type,
            namespace=unquote(namespace) if namespace else None,
            name=unquote(name),
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
        # pkg:type/... - extract type before first /
        type_part = purl[4:].split("/")[0].lower()
        return type_part
    except (IndexError, AttributeError):
        return None


def get_registry_system(purl: str) -> Optional[str]:
    """Get the registry system name for a PURL (for deps.dev API)."""
    purl_type = get_purl_type(purl)
    return PURL_TYPE_TO_SYSTEM.get(purl_type) if purl_type else None


def get_ecosystem(purl: str) -> Optional[str]:
    """Get the ecosystem name for a PURL (for OSV, etc.)."""
    purl_type = get_purl_type(purl)
    return PURL_TYPE_TO_ECOSYSTEM.get(purl_type) if purl_type else None


def is_pypi(purl: str) -> bool:
    """Check if PURL is a PyPI package."""
    return get_purl_type(purl) == "pypi"


def is_npm(purl: str) -> bool:
    """Check if PURL is an npm package."""
    return get_purl_type(purl) == "npm"


def is_maven(purl: str) -> bool:
    """Check if PURL is a Maven package."""
    return get_purl_type(purl) == "maven"


def is_go(purl: str) -> bool:
    """Check if PURL is a Go package."""
    purl_type = get_purl_type(purl)
    return purl_type in ("go", "golang")


def is_cargo(purl: str) -> bool:
    """Check if PURL is a Cargo (Rust) package."""
    return get_purl_type(purl) == "cargo"


def is_nuget(purl: str) -> bool:
    """Check if PURL is a NuGet package."""
    return get_purl_type(purl) == "nuget"
